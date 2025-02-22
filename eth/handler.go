// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package eth

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kar98kar/go-ulogos/common"
	"github.com/kar98kar/go-ulogos/core"
	"github.com/kar98kar/go-ulogos/core/types"
	"github.com/kar98kar/go-ulogos/eth/downloader"
	"github.com/kar98kar/go-ulogos/eth/fetcher"
	"github.com/kar98kar/go-ulogos/ethdb"
	"github.com/kar98kar/go-ulogos/event"
	"github.com/kar98kar/go-ulogos/logger"
	"github.com/kar98kar/go-ulogos/logger/glog"
	"github.com/kar98kar/go-ulogos/p2p"
	"github.com/kar98kar/go-ulogos/p2p/discover"
	"github.com/kar98kar/go-ulogos/pow"
	"github.com/kar98kar/go-ulogos/rlp"
)

const (
	softResponseLimit = 2 * 1024 * 1024 // Target maximum size of returned blocks, headers or node data.
	estHeaderRlpSize  = 500             // Approximate size of an RLP encoded block header

	// txChanSize is the size of channel listening to NewTxsEvent.
	// The number is referenced from the size of tx pool.
	txChanSize = 4096
)

var (
	forkChallengeTimeout = 15 * time.Second // Time allowance for a node to reply to the DAO handshake challenge
)

// errIncompatibleConfig is returned if the requested protocols and configs are
// not compatible (low protocol version restrictions and high requirements).
var errIncompatibleConfig = errors.New("incompatible configuration")

func errResp(code errCode, format string, v ...interface{}) error {
	return fmt.Errorf("%v - %v", code, fmt.Sprintf(format, v...))
}

type ProtocolManager struct {
	networkId uint64

	fastSync   uint32 // Flag whether fast sync is enabled (gets disabled if we already have blocks)
	acceptsTxs uint32 // Flag whether we're considered synchronised (enables transaction processing)

	txpool      txPool
	blockchain  *core.BlockChain
	chaindb     ethdb.Database
	chainConfig *core.ChainConfig
	maxPeers    int

	downloader *downloader.Downloader
	fetcher    *fetcher.Fetcher
	peers      *peerSet

	SubProtocols []p2p.Protocol

	eventMux      *event.TypeMux
	txSub         event.Subscription
	minedBlockSub event.Subscription

	// channels for fetcher, syncer, txsyncLoop
	newPeerCh   chan *peer
	txsyncCh    chan *txsync
	quitSync    chan struct{}
	noMorePeers chan struct{}

	// wait group is used for graceful shutdowns during downloading
	// and processing
	wg sync.WaitGroup
}

// NewProtocolManager returns a new ethereum sub protocol manager. The Ethereum sub protocol manages peers capable
// with the ethereum network.
func NewProtocolManager(config *core.ChainConfig, mode downloader.SyncMode, networkId uint64, mux *event.TypeMux, txpool txPool, pow pow.PoW, blockchain *core.BlockChain, chaindb ethdb.Database) (*ProtocolManager, error) {
	// Create the protocol manager with the base fields
	manager := &ProtocolManager{
		networkId:   networkId,
		eventMux:    mux,
		txpool:      txpool,
		blockchain:  blockchain,
		chaindb:     chaindb,
		chainConfig: config,
		peers:       newPeerSet(),
		newPeerCh:   make(chan *peer),
		noMorePeers: make(chan struct{}),
		txsyncCh:    make(chan *txsync),
		quitSync:    make(chan struct{}),
	}
	// Figure out whether to allow fast sync or not
	if mode == downloader.FastSync && blockchain.CurrentBlock().NumberU64() > 0 {
		glog.V(logger.Warn).Infoln("Blockchain not empty, fast sync disabled")
		glog.D(logger.Warn).Warnln("Blockchain not empty. Fast sync disabled.")
		mode = downloader.FullSync
	}
	if mode == downloader.FastSync {
		manager.fastSync = uint32(1)
		glog.D(logger.Warn).Infoln("Fast sync mode enabled.")
	}
	// Initiate a sub-protocol for every implemented version we can handle
	manager.SubProtocols = make([]p2p.Protocol, 0, len(ProtocolVersions))
	for i, version := range ProtocolVersions {
		// Skip protocol version if incompatible with the mode of operation
		if mode == downloader.FastSync && version < eth63 {
			continue
		}
		// Compatible; initialise the sub-protocol
		version := version // Closure for the run
		manager.SubProtocols = append(manager.SubProtocols, p2p.Protocol{
			Name:    ProtocolName,
			Version: version,
			Length:  ProtocolLengths[i],
			Run: func(p *p2p.Peer, rw p2p.MsgReadWriter) error {
				peer := manager.newPeer(int(version), p, rw)
				select {
				case manager.newPeerCh <- peer:
					manager.wg.Add(1)
					defer manager.wg.Done()
					return manager.handle(peer)
				case <-manager.quitSync:
					return p2p.DiscQuitting
				}
			},
			NodeInfo: func() interface{} {
				return manager.NodeInfo()
			},
			PeerInfo: func(id discover.NodeID) interface{} {
				if p := manager.peers.Peer(fmt.Sprintf("%x", id[:8])); p != nil {
					return p.Info()
				}
				return nil
			},
		})
	}
	if len(manager.SubProtocols) == 0 {
		return nil, errIncompatibleConfig
	}
	// Construct the different synchronisation mechanisms
	manager.downloader = downloader.New(mode, chaindb, manager.eventMux, blockchain, nil, manager.removePeer)

	validator := func(header *types.Header) error {
		return manager.blockchain.Validator().ValidateHeader(header, manager.blockchain.GetHeader(header.ParentHash), true)
	}
	heighter := func() uint64 {
		return blockchain.CurrentBlock().NumberU64()
	}
	inserter := func(blocks types.Blocks) *core.ChainInsertResult {
		if atomic.LoadUint32(&manager.fastSync) == 1 {
			glog.V(logger.Warn).Warnf("Discarded bad propagated block", "number", blocks[0].Number(), "hash", blocks[0].Hash().Hex()[:9])
			glog.D(logger.Warn).Warnf("Discarded bad propagated block", "number", blocks[0].Number(), "hash", blocks[0].Hash().Hex()[:9])
		}
		// Mark initial sync done on any fetcher import
		atomic.StoreUint32(&manager.acceptsTxs, 1)
		return manager.blockchain.InsertChain(blocks)
	}
	manager.fetcher = fetcher.New(mux, blockchain.GetBlock, validator, manager.BroadcastBlock, heighter, inserter, manager.removePeer)

	return manager, nil
}

func (pm *ProtocolManager) removePeer(id string) {
	// Short circuit if the peer was already removed
	peer := pm.peers.Peer(id)
	if peer == nil {
		return
	}
	glog.V(logger.Debug).Infoln("Removing peer", id)
	pm.eventMux.Post(PMHandlerRemoveEvent{
		PMPeersLen: pm.peers.Len(),
		PMBestPeer: pm.peers.BestPeer(),
		Peer:       peer,
	})

	// Unregister the peer from the downloader and Ethereum peer set
	pm.downloader.UnregisterPeer(id)
	if err := pm.peers.Unregister(id); err != nil {
		glog.V(logger.Error).Infoln("Removal failed:", err)
	}
	// Hard disconnect at the networking layer
	if peer != nil {
		peer.Peer.Disconnect(p2p.DiscUselessPeer)
	}
}

func (pm *ProtocolManager) Start(maxPeers int) {
	pm.maxPeers = maxPeers

	// broadcast transactions
	pm.txSub = pm.eventMux.Subscribe(core.TxPreEvent{})
	go pm.txBroadcastLoop()
	// broadcast mined blocks
	pm.minedBlockSub = pm.eventMux.Subscribe(core.NewMinedBlockEvent{})
	go pm.minedBroadcastLoop()

	// start sync handlers
	go pm.syncer()
	go pm.txsyncLoop()
}

func (pm *ProtocolManager) Stop() {
	glog.V(logger.Info).Infoln("Stopping ethereum protocol handler...")

	pm.txSub.Unsubscribe()         // quits txBroadcastLoop
	pm.minedBlockSub.Unsubscribe() // quits blockBroadcastLoop

	// Quit the sync loop.
	// After this send has completed, no new peers will be accepted.
	pm.noMorePeers <- struct{}{}

	// Quit fetcher, txsyncLoop.
	close(pm.quitSync)

	// Disconnect existing sessions.
	// This also closes the gate for any new registrations on the peer set.
	// sessions which are already established but not added to pm.peers yet
	// will exit when they try to register.
	pm.peers.Close()

	// Wait for all peer handler goroutines and the loops to come down.
	pm.wg.Wait()

	glog.V(logger.Info).Infoln("Ethereum protocol handler stopped")
}

func (pm *ProtocolManager) newPeer(pv int, p *p2p.Peer, rw p2p.MsgReadWriter) *peer {
	return newPeer(pv, p, newMeteredMsgWriter(rw))
}

// handle is the callback invoked to manage the life cycle of an eth peer. When
// this function terminates, the peer is disconnected.
func (pm *ProtocolManager) handle(p *peer) error {
	// Ignore maxPeers if this is a trusted peer
	if l := pm.peers.Len(); l >= pm.maxPeers && !p.Peer.Info().Network.Trusted {
		glog.D(logger.Error).Errorln("handler dropping pm.peers.len=", l, "pm.maxPeers=", pm.maxPeers)
		return p2p.DiscTooManyPeers
	}
	glog.V(logger.Debug).Infof("handler: %s ->connected", p)

	// Execute the Ethereum handshake
	td, head, genesis := pm.blockchain.Status()
	if err := p.Handshake(pm.networkId, td, head, genesis); err != nil {
		glog.V(logger.Debug).Infof("handler: %s ->handshakefailed err=%v", p, err)
		return err
	}
	if rw, ok := p.rw.(*meteredMsgReadWriter); ok {
		rw.Init(p.version)
	}
	// Register the peer locally
	glog.V(logger.Debug).Infof("handler: %s ->addpeer", p)
	if err := pm.peers.Register(p); err != nil {
		glog.V(logger.Error).Errorf("handler: %s ->addpeer err=%v", p, err)
		return err
	} else {
		pm.eventMux.Post(PMHandlerAddEvent{
			PMPeersLen: pm.peers.Len(),
			PMBestPeer: pm.peers.BestPeer(),
			Peer:       p,
		})
	}
	defer pm.removePeer(p.id)

	// Register the peer in the downloader. If the downloader considers it banned, we disconnect
	if err := pm.downloader.RegisterPeer(p.id, p.version, p.Name(), p.Head,
		p.RequestHeadersByHash, p.RequestHeadersByNumber, p.RequestBodies,
		p.RequestReceipts, p.RequestNodeData); err != nil {
		return err
	}
	// Propagate existing transactions. new transactions appearing
	// after this will be sent via broadcasts.
	pm.syncTransactions(p)

	pHead, _ := p.Head()
	if headerN, doValidate := pm.getRequiredHashBlockNumber(head, pHead); doValidate {
		// Request the peer's fork block header for extra-dat
		if err := p.RequestHeadersByNumber(headerN, 1, 0, false); err != nil {
			glog.V(logger.Debug).Infof("handler: %s ->headersbynumber err=%v", p, err)
			return err
		}
		// Start a timer to disconnect if the peer doesn't reply in time
		// FIXME: un-hardcode timeout
		p.forkDrop = time.AfterFunc(forkChallengeTimeout, func() {
			glog.V(logger.Debug).Infof("handler: %s ->headersbynumber err='timed out fork-check, dropping'", p)
			pm.removePeer(p.id)
		})
		// Make sure it's cleaned up if the peer dies off
		defer func() {
			if p.forkDrop != nil {
				p.forkDrop.Stop()
				p.forkDrop = nil
			}
		}()
	}

	// main loop. handle incoming messages.
	for {
		if err := pm.handleMsg(p); err != nil {
			glog.V(logger.Debug).Infof("handler: %s ->msghandlefailed err=%v", p, err)
			return err
		}
	}
}

// getRequiredHashBlockNumber returns block number of most relevant fork with requiredHash
// and information is the block validation required.
func (pm *ProtocolManager) getRequiredHashBlockNumber(localHead, peerHead common.Hash) (blockNumber uint64, validate bool) {
	// Drop connections incongruent with any network split or checkpoint that's relevant
	// Check for latest relevant required hash based on our status.
	var headN *big.Int
	headB := pm.blockchain.GetBlock(localHead)
	if headB != nil {
		headN = headB.Number()
	}
	latestReqHashFork := pm.chainConfig.GetLatestRequiredHashFork(headN) // returns nil if no applicable fork with required hash

	// If our local sync progress has not yet reached a height at which a fork with a required hash would be relevant,
	// we can skip this check. This allows the client to be fork agnostic until a configured fork(s) is reached.
	// If we already have the peer's head, the peer is on the right chain, so we can skip required hash validation.
	if latestReqHashFork != nil {
		validate = pm.blockchain.GetBlock(peerHead) == nil
		blockNumber = latestReqHashFork.Block.Uint64()
	}
	return
}

// handleMsg is invoked whenever an inbound message is received from a remote
// peer. The remote connection is torn down upon returning any error.
func (pm *ProtocolManager) handleMsg(p *peer) (err error) {
	// Read the next message from the remote peer, and ensure it's fully consumed
	var unknownMessageCode uint64 = math.MaxUint64
	msg, err := p.rw.ReadMsg()
	if err != nil {
		mlogWireDelegate(p, "receive", unknownMessageCode, -1, nil, err)
		return
	}
	intSize := int(msg.Size)
	if msg.Size > ProtocolMaxMsgSize {
		err = errResp(ErrMsgTooLarge, "%v > %v", msg.Size, ProtocolMaxMsgSize)
		mlogWireDelegate(p, "receive", msg.Code, intSize, nil, err)
		return
	}
	defer msg.Discard()

	// Handle the message depending on its contents
	switch {
	case msg.Code == StatusMsg:
		// Status messages should never arrive after the handshake
		err = errResp(ErrExtraStatusMsg, "uncontrolled status message")
		mlogWireDelegate(p, "receive", StatusMsg, intSize, nil, err)
		return
	// Block header query, collect the requested headers and reply
	case p.version >= eth62 && msg.Code == GetBlockHeadersMsg:
		// Decode the complex header query
		var query getBlockHeadersData
		if e := msg.Decode(&query); e != nil {
			err = errResp(ErrDecode, "%v: %v", msg, e)
			mlogWireDelegate(p, "receive", GetBlockHeadersMsg, intSize, &query, err)
			return
		}
		mlogWireDelegate(p, "receive", GetBlockHeadersMsg, intSize, &query, err)
		hashMode := query.Origin.Hash != (common.Hash{})

		// Gather headers until the fetch or network limits is reached
		var (
			bytes   common.StorageSize
			headers []*types.Header
			unknown bool
		)
		for !unknown && len(headers) < int(query.Amount) && bytes < softResponseLimit && len(headers) < downloader.MaxHeaderFetch {
			// Retrieve the next header satisfying the query
			var origin *types.Header
			if hashMode {
				origin = pm.blockchain.GetHeader(query.Origin.Hash)
			} else {
				origin = pm.blockchain.GetHeaderByNumber(query.Origin.Number)
			}
			if origin == nil {
				break
			}
			headers = append(headers, origin)
			bytes += estHeaderRlpSize

			// Advance to the next header of the query
			switch {
			case query.Origin.Hash != (common.Hash{}) && query.Reverse:
				// Hash based traversal towards the genesis block
				for i := 0; i < int(query.Skip)+1; i++ {
					if header := pm.blockchain.GetHeader(query.Origin.Hash); header != nil {
						query.Origin.Hash = header.ParentHash
					} else {
						unknown = true
						break
					}
				}
			case query.Origin.Hash != (common.Hash{}) && !query.Reverse:
				// Hash based traversal towards the leaf block
				var (
					current = origin.Number.Uint64()
					next    = current + query.Skip + 1
				)
				if next <= current {
					infos, _ := json.MarshalIndent(p.Peer.Info(), "", "  ")
					glog.V(logger.Warn).Infof("%v: GetBlockHeaders skip overflow attack (current %v, skip %v, next %v)\nMalicious peer infos: %s", p, current, query.Skip, next, infos)
					unknown = true
				} else {
					if header := pm.blockchain.GetHeaderByNumber(next); header != nil {
						if pm.blockchain.GetBlockHashesFromHash(header.Hash(), query.Skip+1)[query.Skip] == query.Origin.Hash {
							query.Origin.Hash = header.Hash()
						} else {
							unknown = true
						}
					} else {
						unknown = true
					}
				}
			case query.Reverse:
				// Number based traversal towards the genesis block
				if query.Origin.Number >= query.Skip+1 {
					query.Origin.Number -= (query.Skip + 1)
				} else {
					unknown = true
				}

			case !query.Reverse:
				// Number based traversal towards the leaf block
				query.Origin.Number += (query.Skip + 1)
			}
		}
		return p.SendBlockHeaders(headers)

	case p.version >= eth62 && msg.Code == BlockHeadersMsg:
		// A batch of headers arrived to one of our previous requests
		var headers []*types.Header
		if e := msg.Decode(&headers); e != nil {
			err = errResp(ErrDecode, "msg %v: %v", msg, e)
			mlogWireDelegate(p, "receive", BlockHeadersMsg, intSize, headers, err)
			return
		}
		defer mlogWireDelegate(p, "receive", BlockHeadersMsg, intSize, headers, err)

		// Good will assumption. Even if the peer is ahead of the fork check header but returns
		// empty header response, it might be that the peer is a light client which only keeps
		// the last 256 block headers. Besides it does not prevent network attacks. See #313 for
		// an explaination.
		if len(headers) == 0 && p.forkDrop != nil {
			// Disable the fork drop timeout
			p.forkDrop.Stop()
			p.forkDrop = nil
			return nil
		}
		// Filter out any explicitly requested headers, deliver the rest to the downloader
		filter := len(headers) == 1
		if filter {
			if p.forkDrop != nil {
				// Disable the fork drop timeout
				p.forkDrop.Stop()
				p.forkDrop = nil
			}

			if err = pm.chainConfig.HeaderCheck(headers[0]); err != nil {
				pm.removePeer(p.id)
				return err
			}
			// Irrelevant of the fork checks, send the header to the fetcher just in case
			headers = pm.fetcher.FilterHeaders(p.id, headers, time.Now())
		}
		if len(headers) > 0 || !filter {
			err := pm.downloader.DeliverHeaders(p.id, headers)
			if err != nil {
				glog.V(logger.Debug).Infoln("peer", p.id, err)
			}
		}

	case p.version >= eth62 && msg.Code == GetBlockBodiesMsg:
		// Decode the retrieval message
		msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
		if _, err = msgStream.List(); err != nil {
			return err
		}
		// Gather blocks until the fetch or network limits is reached
		var (
			hash   common.Hash
			bytes  int
			bodies []rlp.RawValue
		)
		for bytes < softResponseLimit && len(bodies) < downloader.MaxBlockFetch {
			// Retrieve the hash of the next block
			if e := msgStream.Decode(&hash); e == rlp.EOL {
				break
			} else if e != nil {
				err = errResp(ErrDecode, "msg %v: %v", msg, e)
				mlogWireDelegate(p, "receive", GetBlockBodiesMsg, intSize, bodies, err)
				return err
			}
			// Retrieve the requested block body, stopping if enough was found
			if data := pm.blockchain.GetBodyRLP(hash); len(data) != 0 {
				bodies = append(bodies, data)
				bytes += len(data)
			}
		}
		mlogWireDelegate(p, "receive", GetBlockBodiesMsg, intSize, bodies, err)
		return p.SendBlockBodiesRLP(bodies)

	case p.version >= eth62 && msg.Code == BlockBodiesMsg:
		// A batch of block bodies arrived to one of our previous requests
		var request blockBodiesData
		// Deliver them all to the downloader for queuing
		if e := msg.Decode(&request); e != nil {
			err = errResp(ErrDecode, "msg %v: %v", msg, e)
			mlogWireDelegate(p, "receive", BlockBodiesMsg, intSize, request, err)
			return
		}
		mlogWireDelegate(p, "receive", BlockBodiesMsg, intSize, request, err)

		transactions := make([][]*types.Transaction, len(request))
		uncles := make([][]*types.Header, len(request))

		for i, body := range request {
			transactions[i] = body.Transactions
			uncles[i] = body.Uncles
		}
		// Filter out any explicitly requested bodies, deliver the rest to the downloader
		filter := len(transactions) > 0 || len(uncles) > 0
		if filter {
			transactions, uncles = pm.fetcher.FilterBodies(p.id, transactions, uncles, time.Now())
		}
		if len(transactions) > 0 || len(uncles) > 0 || !filter {
			if e := pm.downloader.DeliverBodies(p.id, transactions, uncles); e != nil {
				glog.V(logger.Debug).Infoln(e)
			}
		}

	case p.version >= eth63 && msg.Code == GetNodeDataMsg:
		// Decode the retrieval message
		msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
		if _, err = msgStream.List(); err != nil {
			mlogWireDelegate(p, "receive", GetNodeDataMsg, intSize, [][]byte{}, err)
			return err
		}
		// Gather state data until the fetch or network limits is reached
		var (
			hash  common.Hash
			bytes int
			data  [][]byte
		)
		for bytes < softResponseLimit && len(data) < downloader.MaxStateFetch {
			// Retrieve the hash of the next state entry
			if e := msgStream.Decode(&hash); e == rlp.EOL {
				break
			} else if e != nil {
				err = errResp(ErrDecode, "msg %v: %v", msg, e)
				mlogWireDelegate(p, "receive", GetNodeDataMsg, intSize, data, err)
				return
			}
			// Retrieve the requested state entry, stopping if enough was found
			if entry, e := pm.chaindb.Get(hash.Bytes()); e == nil {
				data = append(data, entry)
				bytes += len(entry)
			}
		}
		mlogWireDelegate(p, "receive", GetNodeDataMsg, intSize, data, err)
		return p.SendNodeData(data)

	case p.version >= eth63 && msg.Code == NodeDataMsg:
		// A batch of node state data arrived to one of our previous requests
		var data [][]byte

		if e := msg.Decode(&data); e != nil {
			err = errResp(ErrDecode, "msg %v: %v", msg, e)
			mlogWireDelegate(p, "receive", NodeDataMsg, intSize, data, err)
			return
		}
		mlogWireDelegate(p, "receive", NodeDataMsg, intSize, data, err)
		// Deliver all to the downloader
		if e := pm.downloader.DeliverNodeData(p.id, data); e != nil {
			glog.V(logger.Core).Warnf("failed to deliver node state data: %v", e)
		}

	case p.version >= eth63 && msg.Code == GetReceiptsMsg:
		// Decode the retrieval message
		msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
		if _, err = msgStream.List(); err != nil {
			mlogWireDelegate(p, "receive", GetReceiptsMsg, intSize, []rlp.RawValue{}, err)
			return err
		}
		// Gather state data until the fetch or network limits is reached
		var (
			hash     common.Hash
			bytes    int
			receipts []rlp.RawValue
		)
		for bytes < softResponseLimit && len(receipts) < downloader.MaxReceiptFetch {
			// Retrieve the hash of the next block
			if e := msgStream.Decode(&hash); e == rlp.EOL {
				break
			} else if e != nil {
				err = errResp(ErrDecode, "msg %v: %v", msg, e)
				mlogWireDelegate(p, "receive", GetReceiptsMsg, intSize, receipts, err)
				return
			}
			// Retrieve the requested block's receipts, skipping if unknown to us
			results := core.GetBlockReceipts(pm.chaindb, hash)
			if results == nil {
				if header := pm.blockchain.GetHeader(hash); header == nil || header.ReceiptHash != types.EmptyRootHash {
					continue
				}
			}
			// If known, encode and queue for response packet
			if encoded, err := rlp.EncodeToBytes(results); err != nil {
				glog.V(logger.Error).Infof("failed to encode receipt: %v", err)
			} else {
				receipts = append(receipts, encoded)
				bytes += len(encoded)
			}
		}
		mlogWireDelegate(p, "receive", GetReceiptsMsg, intSize, receipts, err)
		return p.SendReceiptsRLP(receipts)

	case p.version >= eth63 && msg.Code == ReceiptsMsg:
		// A batch of receipts arrived to one of our previous requests
		var receipts [][]*types.Receipt
		if err := msg.Decode(&receipts); err != nil {
			mlogWireDelegate(p, "receive", ReceiptsMsg, intSize, receipts, err)
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		mlogWireDelegate(p, "receive", ReceiptsMsg, intSize, receipts, err)
		// Deliver all to the downloader
		if err := pm.downloader.DeliverReceipts(p.id, receipts); err != nil {
			glog.V(logger.Core).Warnf("failed to deliver receipts: %v", err)
		}

	case msg.Code == NewBlockHashesMsg:
		// Retrieve and deserialize the remote new block hashes notification
		var announces newBlockHashesData // = []announce{}

		if p.version < eth62 {
			// We're running the old protocol, make block number unknown (0)
			var hashes []common.Hash
			if e := msg.Decode(&hashes); e != nil {
				err = errResp(ErrDecode, "%v: %v", msg, e)
				mlogWireDelegate(p, "receive", NewBlockHashesMsg, intSize, announces, err)
				return
			}
			for _, hash := range hashes {
				announces = append(announces, announce{hash, 0})
			}
		} else {
			// Otherwise extract both block hash and number
			var request newBlockHashesData
			if e := msg.Decode(&request); e != nil {
				err = errResp(ErrDecode, "%v: %v", msg, e)
				mlogWireDelegate(p, "receive", NewBlockHashesMsg, intSize, announces, err)
				return
			}
			for _, block := range request {
				announces = append(announces, announce{block.Hash, block.Number})
			}
		}
		mlogWireDelegate(p, "receive", NewBlockHashesMsg, intSize, announces, err)
		// Mark the hashes as present at the remote node
		for _, block := range announces {
			p.MarkBlock(block.Hash)
			p.SetHead(block.Hash, p.td)
		}
		// Schedule all the unknown hashes for retrieval
		unknown := make([]announce, 0, len(announces))
		for _, block := range announces {
			if !pm.blockchain.HasBlock(block.Hash) {
				unknown = append(unknown, block)
			}
		}
		for _, block := range unknown {
			// TODO Breaking /eth tests
			pm.fetcher.Notify(p.id, block.Hash, block.Number, time.Now(), p.RequestOneHeader, p.RequestBodies)
		}

	case msg.Code == NewBlockMsg:
		// Retrieve and decode the propagated block
		var request newBlockData

		if e := msg.Decode(&request); e != nil {
			err = errResp(ErrDecode, "%v: %v", msg, e)
			mlogWireDelegate(p, "receive", NewBlockMsg, intSize, request, err)
			return
		}
		if e := request.Block.ValidateFields(); e != nil {
			err = errResp(ErrDecode, "block validation %v: %v", msg, e)
			mlogWireDelegate(p, "receive", NewBlockMsg, intSize, request, err)
			return
		}

		mlogWireDelegate(p, "receive", NewBlockMsg, intSize, request, err)

		request.Block.ReceivedAt = msg.ReceivedAt
		request.Block.ReceivedFrom = p

		// Mark the peer as owning the block and schedule it for import
		p.MarkBlock(request.Block.Hash())
		pm.fetcher.Enqueue(p.id, request.Block)

		// Assuming the block is importable by the peer, but possibly not yet done so,
		// calculate the head hash and TD that the peer truly must have.
		var (
			trueHead = request.Block.ParentHash()
			trueTD   = new(big.Int).Sub(request.TD, request.Block.Difficulty())
		)
		// Update the peers total difficulty if better than the previous
		if _, td := p.Head(); trueTD.Cmp(td) > 0 {
			glog.V(logger.Debug).Infof("Peer %s: setting head: tdWas=%v trueTD=%v", p.id, td, trueTD)
			p.SetHead(trueHead, trueTD)

			// Schedule a sync if above ours. Note, this will not fire a sync for a gap of
			// a singe block (as the true TD is below the propagated block), however this
			// scenario should easily be covered by the fetcher.
			currentBlock := pm.blockchain.CurrentBlock()
			if localTd := pm.blockchain.GetTd(currentBlock.Hash()); trueTD.Cmp(localTd) > 0 {
				if !pm.downloader.Synchronising() {
					glog.V(logger.Info).Infof("Peer %s: localTD=%v (<) peerTrueTD=%v, synchronising", p.id, localTd, trueTD)
					go pm.synchronise(p)
				}
			} else {
				glog.V(logger.Detail).Infof("Peer %s: localTD=%v (>=) peerTrueTD=%v, NOT synchronising", p.id, localTd, trueTD)
			}
		} else {
			glog.V(logger.Detail).Infof("Peer %s: NOT setting head: tdWas=%v trueTD=%v", p.id, td, trueTD)
		}

	case msg.Code == TxMsg:
		// Transactions arrived, make sure we have a valid and fresh chain to handle them
		if atomic.LoadUint32(&pm.acceptsTxs) == 0 {
			mlogWireDelegate(p, "receive", TxMsg, intSize, []*types.Transaction{}, errors.New("not synced"))
			break
		}
		// Transactions can be processed, parse all of them and deliver to the pool
		var txs []*types.Transaction
		if e := msg.Decode(&txs); e != nil {
			err = errResp(ErrDecode, "msg %v: %v", msg, e)
			mlogWireDelegate(p, "receive", TxMsg, intSize, txs, err)
			return
		}
		mlogWireDelegate(p, "receive", TxMsg, intSize, txs, err)
		for i, tx := range txs {
			// Validate and mark the remote transaction
			if tx == nil {
				return errResp(ErrDecode, "transaction %d is nil", i)
			}
			p.MarkTransaction(tx.Hash())
		}
		pm.txpool.AddTransactions(txs)

	default:
		err = errResp(ErrInvalidMsgCode, "%v", msg.Code)
		mlogWireDelegate(p, "receive", unknownMessageCode, intSize, nil, err)
		return
	}
	return nil
}

// BroadcastBlock will either propagate a block to a subset of it's peers, or
// will only announce it's availability (depending what's requested).
func (pm *ProtocolManager) BroadcastBlock(block *types.Block, propagate bool) {
	hash := block.Hash()
	peers := pm.peers.PeersWithoutBlock(hash)

	// If propagation is requested, send to a subset of the peer
	if propagate {
		// Calculate the TD of the block (it's not imported yet, so block.Td is not valid)
		var td *big.Int
		if parent := pm.blockchain.GetBlock(block.ParentHash()); parent != nil {
			td = new(big.Int).Add(block.Difficulty(), pm.blockchain.GetTd(block.ParentHash()))
		} else {
			glog.V(logger.Error).Infof("propagating dangling block #%d [%x]", block.NumberU64(), hash[:4])
			return
		}
		// Send the block to a subset of our peers
		transfer := peers[:int(math.Sqrt(float64(len(peers))))]
		for _, peer := range transfer {
			peer.AsyncSendNewBlock(block, td)
		}
		glog.V(logger.Detail).Infof("propagated block %x to %d peers in %v", hash[:4], len(transfer), time.Since(block.ReceivedAt))
	}
	// Otherwise if the block is indeed in our own chain, announce it
	if pm.blockchain.HasBlock(block.Hash()) {
		for _, peer := range peers {
			peer.AsyncSendNewBlockHash(block)
		}
		glog.V(logger.Detail).Infof("announced block %x to %d peers in %v", hash[:4], len(peers), time.Since(block.ReceivedAt))
	}
}

// BroadcastTx will propagate a transaction to all peers which are not known to
// already have the given transaction.
func (pm *ProtocolManager) BroadcastTx(hash common.Hash, tx *types.Transaction) {
	// Broadcast transaction to a batch of peers not knowing about it
	peers := pm.peers.PeersWithoutTx(hash)
	//FIXME include this again: peers = peers[:int(math.Sqrt(float64(len(peers))))]
	for _, peer := range peers {
		peer.AsyncSendTransactions(types.Transactions{tx})
	}
	glog.V(logger.Detail).Infof("broadcast tx [%s] to %d peers", tx.Hash().Hex(), len(peers))
}

// Mined broadcast loop
func (self *ProtocolManager) minedBroadcastLoop() {
	// automatically stops if unsubscribe
	for obj := range self.minedBlockSub.Chan() {
		switch ev := obj.Data.(type) {
		case core.NewMinedBlockEvent:
			self.BroadcastBlock(ev.Block, true)  // First propagate block to peers
			self.BroadcastBlock(ev.Block, false) // Only then announce to the rest
		}
	}
}

func (self *ProtocolManager) txBroadcastLoop() {
	// automatically stops if unsubscribe
	for obj := range self.txSub.Chan() {
		event := obj.Data.(core.TxPreEvent)
		self.BroadcastTx(event.Tx.Hash(), event.Tx)
	}
}

// EthNodeInfo represents a short summary of the Ethereum sub-protocol metadata known
// about the host peer.
type EthNodeInfo struct {
	Network    int         `json:"network"`    // Ethereum network ID (1=Mainnet, 2=Morden)
	Difficulty *big.Int    `json:"difficulty"` // Total difficulty of the host's blockchain
	Genesis    common.Hash `json:"genesis"`    // SHA3 hash of the host's genesis block
	Head       common.Hash `json:"head"`       // SHA3 hash of the host's best owned block
}

// NodeInfo retrieves some protocol metadata about the running host node.
func (self *ProtocolManager) NodeInfo() *EthNodeInfo {
	return &EthNodeInfo{
		Network:    int(self.networkId),
		Difficulty: self.blockchain.GetTd(self.blockchain.CurrentBlock().Hash()),
		Genesis:    self.blockchain.Genesis().Hash(),
		Head:       self.blockchain.CurrentBlock().Hash(),
	}
}
