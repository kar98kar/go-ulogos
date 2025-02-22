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

package discover

import (
	"bytes"
	"container/list"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/kar98kar/go-ulogos/crypto"
	"github.com/kar98kar/go-ulogos/logger"
	"github.com/kar98kar/go-ulogos/logger/glog"
	"github.com/kar98kar/go-ulogos/p2p/distip"
	"github.com/kar98kar/go-ulogos/p2p/nat"
	"github.com/kar98kar/go-ulogos/rlp"
)

const Version = 4

// Errors
var (
	errPacketTooSmall   = errors.New("too small")
	errBadHash          = errors.New("bad hash")
	errExpired          = errors.New("expired")
	errUnsolicitedReply = errors.New("unsolicited reply")
	errUnknownNode      = errors.New("unknown node")
	errReservedAddress  = errors.New("reserved address neighbor from non-reserved source")
	errInvalidIp        = errors.New("invalid ip")
	errTimeout          = errors.New("RPC timeout")
	errClockWarp        = errors.New("reply deadline too far in the future")
	errClosed           = errors.New("socket closed")

	// Note: golang/net.IP provides some similar functionality via #IsLinkLocalUnicast, ...Multicast, etc.
	// I would rather duplicate the information in a unified and comprehensive system than
	// patch-in with a couple available library methods.
	// I expect many of these occasions will be very unlikely.
	//
	// IPv4
	Ipv4ReservedRangeThis               = [2]net.IP{net.ParseIP("0.0.0.0"), net.ParseIP("0.255.255.255")}
	Ipv4ReservedRangePrivateNetwork     = [2]net.IP{net.ParseIP("10.0.0.0"), net.ParseIP("10.255.255.255")}
	ipv4ReservedRangeProviderSubscriber = [2]net.IP{net.ParseIP("100.64.0.0"), net.ParseIP("100.127.255.255")}
	Ipv4ReservedRangeLoopback           = [2]net.IP{net.ParseIP("127.0.0.0"), net.ParseIP("127.255.255.255")}
	ipv4ReservedRangeLinkLocal          = [2]net.IP{net.ParseIP("169.254.0.0"), net.ParseIP("169.254.255.255")}
	ipv4ReservedRangeLocalPrivate1      = [2]net.IP{net.ParseIP("172.16.0.0"), net.ParseIP("172.31.255.255")}
	ipv4ReservedRangeSpecialPurpose     = [2]net.IP{net.ParseIP("192.0.0.0"), net.ParseIP("192.0.0.255")}
	ipv4ReservedRangeTestNet1           = [2]net.IP{net.ParseIP("192.0.2.0"), net.ParseIP("192.0.2.255")}
	ipv4ReservedRange6to4               = [2]net.IP{net.ParseIP("192.88.99.0"), net.ParseIP("192.88.99.255")}
	Ipv4ReservedRangeLocalPrivate2      = [2]net.IP{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255")}
	ipv4ReservedRangeSubnets            = [2]net.IP{net.ParseIP("198.18.0.0"), net.ParseIP("198.19.255.255")}
	ipv4ReservedRangeTestNet2           = [2]net.IP{net.ParseIP("198.51.100.0"), net.ParseIP("198.51.100.255")}
	ipv4ReservedRangeTestNet3           = [2]net.IP{net.ParseIP("203.0.113.0"), net.ParseIP("203.0.113.255")}
	ipv4ReservedRangeMulticast          = [2]net.IP{net.ParseIP("224.0.0.0"), net.ParseIP("239.255.255.255")}
	ipv4ReservedRangeFuture             = [2]net.IP{net.ParseIP("240.0.0.0"), net.ParseIP("255.255.255.254")}
	ipv4ReservedRangeLimitedBroadcast   = [2]net.IP{net.ParseIP("255.255.255.255"), net.ParseIP("255.255.255.255")}

	// IPv6
	ipv6ReservedRangeUnspecified   = [2]net.IP{net.ParseIP("::"), net.ParseIP("::")}
	Ipv6ReservedRangeLoopback      = [2]net.IP{net.ParseIP("::1"), net.ParseIP("::1")}
	ipv6ReservedRangeDocumentation = [2]net.IP{net.ParseIP("2001:db8::"), net.ParseIP("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")}
	ipv6ReservedRange6to4          = [2]net.IP{net.ParseIP("2002::"), net.ParseIP("2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff")}
	ipv6ReservedRangeUniqueLocal   = [2]net.IP{net.ParseIP("fc00::"), net.ParseIP("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")}
	ipv6ReservedRangeLinkLocal     = [2]net.IP{net.ParseIP("fe80::"), net.ParseIP("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff")}
	ipv6ReservedRangeMulticast     = [2]net.IP{net.ParseIP("ff00::"), net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")}
)

// Timeouts
const (
	respTimeout = 500 * time.Millisecond
	expiration  = 20 * time.Second

	ntpFailureThreshold = 32               // Continuous timeouts after which to check NTP
	ntpWarningCooldown  = 10 * time.Minute // Minimum amount of time to pass before repeating NTP warning
	driftThreshold      = 10 * time.Second // Allowed clock drift before warning user
)

// RPC packet types
const (
	pingPacket = iota + 1 // zero is 'reserved'
	pongPacket
	findnodePacket
	neighborsPacket
)

// RPC request structures
type (
	ping struct {
		Version    uint
		From, To   rpcEndpoint
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// pong is the reply to ping.
	pong struct {
		// This field should mirror the UDP envelope address
		// of the ping packet, which provides a way to discover the
		// the external address (after NAT).
		To rpcEndpoint

		ReplyTok   []byte // This contains the hash of the ping packet.
		Expiration uint64 // Absolute timestamp at which the packet becomes invalid.
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// findnode is a query for nodes close to the given target.
	findnode struct {
		Target     NodeID // doesn't need to be an actual public key
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// reply to findnode
	neighbors struct {
		Nodes      []rpcNode
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	rpcNode struct {
		IP  net.IP // len 4 for IPv4 or 16 for IPv6
		UDP uint16 // for discovery protocol
		TCP uint16 // for RLPx protocol
		ID  NodeID
	}

	rpcEndpoint struct {
		IP  net.IP // len 4 for IPv4 or 16 for IPv6
		UDP uint16 // for discovery protocol
		TCP uint16 // for RLPx protocol
	}
)

func makeEndpoint(addr *net.UDPAddr, tcpPort uint16) rpcEndpoint {
	ip := addr.IP.To4()
	if ip == nil {
		ip = addr.IP.To16()
	}
	return rpcEndpoint{IP: ip, UDP: uint16(addr.Port), TCP: tcpPort}
}

func (t *udp) nodeFromRPC(sender *net.UDPAddr, rn rpcNode) (*Node, error) {
	if rn.UDP <= 1024 {
		return nil, errors.New("low port")
	}
	if err := distip.CheckRelayIP(sender.IP, rn.IP); err != nil {
		return nil, err
	}
	if t.netrestrict != nil && !t.netrestrict.Contains(rn.IP) {
		return nil, errors.New("not contained in netrestrict whitelist")
	}
	n := NewNode(rn.ID, rn.IP, rn.UDP, rn.TCP)
	err := n.validateComplete()
	return n, err
}

func nodeToRPC(n *Node) rpcNode {
	return rpcNode{ID: n.ID, IP: n.IP, UDP: n.UDP, TCP: n.TCP}
}

type packet interface {
	handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error
}

type conn interface {
	ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error)
	WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error)
	Close() error
	LocalAddr() net.Addr
}

// udp implements the RPC protocol.
type udp struct {
	conn        conn
	netrestrict *distip.Netlist
	priv        *ecdsa.PrivateKey
	ourEndpoint rpcEndpoint

	addpending chan *pending
	gotreply   chan reply

	closing chan struct{}

	*Table
}

// pending represents a pending reply.
//
// some implementations of the protocol wish to send more than one
// reply packet to findnode. in general, any neighbors packet cannot
// be matched up with a specific findnode packet.
//
// our implementation handles this by storing a callback function for
// each pending reply. incoming packets from a node are dispatched
// to all the callback functions for that node.
type pending struct {
	// these fields must match in the reply.
	from  NodeID
	ptype byte

	// time when the request must complete
	deadline time.Time

	// callback is called when a matching reply arrives. if it returns
	// true, the callback is removed from the pending reply queue.
	// if it returns false, the reply is considered incomplete and
	// the callback will be invoked again for the next matching reply.
	callback func(resp interface{}) (done bool)

	// errc receives nil when the callback indicates completion or an
	// error if no further reply is received within the timeout.
	errc chan<- error
}

type reply struct {
	from  NodeID
	ptype byte
	data  interface{}
	// loop indicates whether there was
	// a matching request by sending on this channel.
	matched chan<- bool
}

// ListenUDP returns a new table that listens for UDP packets on laddr.
func ListenUDP(priv *ecdsa.PrivateKey, laddr string, natm nat.Interface, nodeDBPath string) (*Table, error) {
	addr, err := net.ResolveUDPAddr("udp", laddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	tab, _, err := newUDP(priv, conn, natm, nodeDBPath)
	if err != nil {
		return nil, err
	}
	glog.V(logger.Info).Infoln("Listening,", tab.self)
	glog.D(logger.Warn).Infoln("UDP listening. Client enode:", logger.ColorGreen(tab.self.String()))

	return tab, nil
}

func newUDP(priv *ecdsa.PrivateKey, c conn, natm nat.Interface, nodeDBPath string) (*Table, *udp, error) {
	udp := &udp{
		conn:       c,
		priv:       priv,
		closing:    make(chan struct{}),
		gotreply:   make(chan reply),
		addpending: make(chan *pending),
	}
	realaddr := c.LocalAddr().(*net.UDPAddr)
	if natm != nil {
		if !realaddr.IP.IsLoopback() {
			go nat.Map(natm, udp.closing, "udp", realaddr.Port, realaddr.Port, "ethereum discovery")
		}
		// TODO: react to external IP changes over time.
		if ext, err := natm.ExternalIP(); err == nil {
			realaddr = &net.UDPAddr{IP: ext, Port: realaddr.Port}
		}
	}
	// TODO: separate TCP port
	udp.ourEndpoint = makeEndpoint(realaddr, uint16(realaddr.Port))
	tab, err := newTable(udp, PubkeyID(&priv.PublicKey), realaddr, nodeDBPath)
	if err != nil {
		return nil, nil, err
	}
	udp.Table = tab

	go udp.loop()
	go udp.readLoop()
	return udp.Table, udp, nil
}

func (t *udp) close() {
	close(t.closing)
	t.conn.Close()
	// TODO: wait for the loops to end.
}

// ping sends a ping message to the given node and waits for a reply.
func (t *udp) ping(toid NodeID, toaddr *net.UDPAddr) error {
	// TODO: maybe check for ReplyTo field in callback to measure RTT
	errc := t.pending(toid, pongPacket, func(interface{}) bool { return true })
	t.send(toaddr, pingPacket, ping{
		Version:    Version,
		From:       t.ourEndpoint,
		To:         makeEndpoint(toaddr, 0), // TODO: maybe use known TCP port from DB
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
	return <-errc
}

func (t *udp) waitping(from NodeID) error {
	return <-t.pending(from, pingPacket, func(interface{}) bool { return true })
}

// findnode sends a findnode request to the given node and waits until
// the node has sent up to k neighbors.
func (t *udp) findnode(toid NodeID, toaddr *net.UDPAddr, target NodeID) ([]*Node, error) {
	nodes := make([]*Node, 0, bucketSize)
	nreceived := 0
	errc := t.pending(toid, neighborsPacket, func(r interface{}) bool {
		reply := r.(*neighbors)
		for _, rn := range reply.Nodes {
			nreceived++
			if n, err := t.nodeFromRPC(toaddr, rn); err == nil {
				nodes = append(nodes, n)
			}
		}
		return nreceived >= bucketSize
	})
	t.send(toaddr, findnodePacket, findnode{
		Target:     target,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
	err := <-errc

	// remove nodes from *neighbors response
	// where the originating address (toaddr) is *not* reserved and the given neighbor is reserved.
	// This prevents irrelevant private network addresses from causing
	// attempted discoveries on reserved ips that are not on
	// our node's network.
	// > https://en.wikipedia.org/wiki/Reserved_IP_addresses
	// > https://github.com/kar98kar/go-ulogos/issues/283
	// > https://tools.ietf.org/html/rfc5737
	// > https://tools.ietf.org/html/rfc3849
	if !isReserved(toaddr.IP) {
		var okNodes []*Node
		for _, n := range nodes {
			if isReserved(n.IP) {
				glog.V(logger.Detail).Warnf("%v: removing from neighbors: toaddr: %v, id: %v, ip: %v", errReservedAddress, toaddr, n.ID, n.IP)
				continue
			}
			okNodes = append(okNodes, n)
		}
		nodes = okNodes
	}

	return nodes, err
}

// pending adds a reply callback to the pending reply queue.
// see the documentation of type pending for a detailed explanation.
func (t *udp) pending(id NodeID, ptype byte, callback func(interface{}) bool) <-chan error {
	ch := make(chan error, 1)
	p := &pending{from: id, ptype: ptype, callback: callback, errc: ch}
	select {
	case t.addpending <- p:
		// loop will handle it
	case <-t.closing:
		ch <- errClosed
	}
	return ch
}

func (t *udp) handleReply(from NodeID, ptype byte, req packet) bool {
	matched := make(chan bool, 1)
	select {
	case t.gotreply <- reply{from, ptype, req, matched}:
		// loop will handle it
		return <-matched
	case <-t.closing:
		return false
	}
}

// loop runs in its own goroutine. it keeps track of
// the refresh timer and the pending reply queue.
func (t *udp) loop() {
	var (
		plist        = list.New()
		timeout      = time.NewTimer(0)
		nextTimeout  *pending // head of plist when timeout was last reset
		contTimeouts = 0      // number of continuous timeouts to do NTP checks
		ntpWarnTime  = time.Unix(0, 0)
	)
	<-timeout.C // ignore first timeout
	defer timeout.Stop()

	resetTimeout := func() {
		if plist.Front() == nil || nextTimeout == plist.Front().Value {
			return
		}
		// Start the timer so it fires when the next pending reply has expired.
		now := time.Now()
		for el := plist.Front(); el != nil; el = el.Next() {
			nextTimeout = el.Value.(*pending)
			if dist := nextTimeout.deadline.Sub(now); dist < 2*respTimeout {
				timeout.Reset(dist)
				return
			}
			// Remove pending replies whose deadline is too far in the
			// future. These can occur if the system clock jumped
			// backwards after the deadline was assigned.
			nextTimeout.errc <- errClockWarp
			plist.Remove(el)
		}
		nextTimeout = nil
		timeout.Stop()
	}

	for {
		resetTimeout()

		select {
		case <-t.closing:
			for el := plist.Front(); el != nil; el = el.Next() {
				el.Value.(*pending).errc <- errClosed
			}
			return

		case p := <-t.addpending:
			p.deadline = time.Now().Add(respTimeout)
			plist.PushBack(p)

		case r := <-t.gotreply:
			var matched bool
			for el := plist.Front(); el != nil; el = el.Next() {
				p := el.Value.(*pending)
				if p.from == r.from && p.ptype == r.ptype {
					matched = true
					// Remove the matcher if its callback indicates
					// that all replies have been received. This is
					// required for packet types that expect multiple
					// reply packets.
					if p.callback(r.data) {
						p.errc <- nil
						plist.Remove(el)
					}
					// Reset the continuous timeout counter (time drift detection)
					contTimeouts = 0
				}
			}
			r.matched <- matched

		case now := <-timeout.C:
			nextTimeout = nil

			// Notify and remove callbacks whose deadline is in the past.
			for el := plist.Front(); el != nil; el = el.Next() {
				p := el.Value.(*pending)
				if now.After(p.deadline) || now.Equal(p.deadline) {
					p.errc <- errTimeout
					plist.Remove(el)
					contTimeouts++
				}
			}
			// If we've accumulated too many timeouts, do an NTP time sync check
			if contTimeouts > ntpFailureThreshold {
				if time.Since(ntpWarnTime) >= ntpWarningCooldown {
					ntpWarnTime = time.Now()
					go checkClockDrift()
				}
				contTimeouts = 0
			}
		}
	}
}

const (
	macSize  = 256 / 8
	sigSize  = 520 / 8
	headSize = macSize + sigSize // space of packet frame data
)

var (
	headSpace = make([]byte, headSize)

	// Neighbors replies are sent across multiple packets to
	// stay below the 1280 byte limit. We compute the maximum number
	// of entries by stuffing a packet until it grows too large.
	maxNeighbors int
)

func init() {
	p := neighbors{Expiration: ^uint64(0)}
	maxSizeNode := rpcNode{IP: make(net.IP, 16), UDP: ^uint16(0), TCP: ^uint16(0)}
	for n := 0; ; n++ {
		p.Nodes = append(p.Nodes, maxSizeNode)
		size, _, err := rlp.EncodeToReader(p)
		if err != nil {
			// If this ever happens, it will be caught by the unit tests.
			panic("cannot encode: " + err.Error())
		}
		if headSize+size+1 >= 1280 {
			maxNeighbors = n
			break
		}
	}
}

func (t *udp) send(toaddr *net.UDPAddr, ptype byte, req interface{}) error {
	packet, err := encodePacket(t.priv, ptype, req)
	if err != nil {
		return err
	}
	if logger.MlogEnabled() {
		switch ptype {
		// @sorpass: again, performance penalty?
		case pingPacket:
			mlogPingSendTo.AssignDetails(
				toaddr.String(),
				len(packet),
			).Send(mlogDiscover)
		case pongPacket:
			mlogPongSendTo.AssignDetails(
				toaddr.String(),
				len(packet),
			).Send(mlogDiscover)
		case findnodePacket:
			mlogFindNodeSendTo.AssignDetails(
				toaddr.String(),
				len(packet),
			).Send(mlogDiscover)
		case neighborsPacket:
			mlogNeighborsSendTo.AssignDetails(
				toaddr.String(),
				len(packet),
			).Send(mlogDiscover)
		}
	}
	if glog.V(logger.Detail) {
		glog.Infof(">>> %v %T\n", toaddr, req)
	}

	if _, err = t.conn.WriteToUDP(packet, toaddr); err != nil {
		glog.V(logger.Detail).Infoln("UDP send failed:", err)
	}
	return err
}

func encodePacket(priv *ecdsa.PrivateKey, ptype byte, req interface{}) ([]byte, error) {
	b := new(bytes.Buffer)
	b.Write(headSpace)
	b.WriteByte(ptype)
	if err := rlp.Encode(b, req); err != nil {
		glog.V(logger.Error).Infoln("error encoding packet:", err)
		return nil, err
	}
	packet := b.Bytes()
	sig, err := crypto.Sign(crypto.Keccak256(packet[headSize:]), priv)
	if err != nil {
		glog.V(logger.Error).Infoln("could not sign packet:", err)
		return nil, err
	}
	copy(packet[macSize:], sig)
	// add the hash to the front. Note: this doesn't protect the
	// packet in any way. Our public key will be part of this hash in
	// The future.
	copy(packet, crypto.Keccak256(packet[macSize:]))
	return packet, nil
}

func isTemporaryError(err error) bool {
	tempErr, ok := err.(interface {
		Temporary() bool
	})
	return ok && tempErr.Temporary() || isPacketTooBig(err)
}

// readLoop runs in its own goroutine. it handles incoming UDP packets.
func (t *udp) readLoop() {
	defer t.conn.Close()
	// Discovery packets are defined to be no larger than 1280 bytes.
	// Packets larger than this size will be cut at the end and treated
	// as invalid because their hash won't match.
	buf := make([]byte, 1280)
	for {
		nbytes, from, err := t.conn.ReadFromUDP(buf)
		if isTemporaryError(err) {
			// Ignore temporary read errors.
			glog.V(logger.Debug).Infof("Temporary read error: %v", err)
			continue
		} else if err != nil {
			// Shut down the loop for permament errors.
			glog.V(logger.Debug).Infof("Read error: %v", err)
			return
		}
		t.handlePacket(from, buf[:nbytes])
	}
}

func (t *udp) handlePacket(from *net.UDPAddr, buf []byte) error {
	packet, fromID, hash, err := decodePacket(buf)
	if err != nil {
		glog.V(logger.Debug).Infof("Bad packet from %v: %v\n", from, err)
		return err
	}
	status := "ok"
	if err = packet.handle(t, from, fromID, hash); err != nil {
		status = err.Error()
	}
	if logger.MlogEnabled() {
		// Use fmt Type interpolator to decide kind of request received,
		// since packet is an interface with 1 method: handle.
		switch p := fmt.Sprintf("%T", packet); p {
		case "*discover.ping":
			mlogPingHandleFrom.AssignDetails(
				from.String(),
				fromID.String(),
				len(buf),
			).Send(mlogDiscover)
		case "*discover.pong":
			mlogPongHandleFrom.AssignDetails(
				from.String(),
				fromID.String(),
				len(buf),
			).Send(mlogDiscover)
		case "*discover.findnode":
			mlogFindNodeHandleFrom.AssignDetails(
				from.String(),
				fromID.String(),
				len(buf),
			).Send(mlogDiscover)
		case "*discover.neighbors":
			mlogNeighborsHandleFrom.AssignDetails(
				from.String(),
				fromID.String(),
				len(buf),
			).Send(mlogDiscover)
		}
	}
	if glog.V(logger.Detail) {
		glog.Infof("<<< %v %T: %s\n", from, packet, status)
	}
	return err
}

func decodePacket(buf []byte) (packet, NodeID, []byte, error) {
	if len(buf) < headSize+1 {
		return nil, NodeID{}, nil, errPacketTooSmall
	}
	hash, sig, sigdata := buf[:macSize], buf[macSize:headSize], buf[headSize:]
	shouldhash := crypto.Keccak256(buf[macSize:])
	if !bytes.Equal(hash, shouldhash) {
		return nil, NodeID{}, nil, errBadHash
	}
	fromID, err := recoverNodeID(crypto.Keccak256(buf[headSize:]), sig)
	if err != nil {
		return nil, NodeID{}, hash, err
	}
	var req packet
	switch ptype := sigdata[0]; ptype {
	case pingPacket:
		req = new(ping)
	case pongPacket:
		req = new(pong)
	case findnodePacket:
		req = new(findnode)
	case neighborsPacket:
		req = new(neighbors)
	default:
		return nil, fromID, hash, fmt.Errorf("unknown type: %d", ptype)
	}
	s := rlp.NewStream(bytes.NewReader(sigdata[1:]), 0)
	err = s.Decode(req)
	return req, fromID, hash, err
}

func (req *ping) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	if expired(req.Expiration) {
		return errExpired
	}
	t.send(from, pongPacket, pong{
		To:         makeEndpoint(from, req.From.TCP),
		ReplyTok:   mac,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
	if !t.handleReply(fromID, pingPacket, req) {
		// Note: we're ignoring the provided IP address right now
		go t.bond(true, fromID, from, req.From.TCP)
	}
	return nil
}

func (req *pong) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	if expired(req.Expiration) {
		return errExpired
	}
	if !t.handleReply(fromID, pongPacket, req) {
		return errUnsolicitedReply
	}
	return nil
}

func (req *findnode) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	if expired(req.Expiration) {
		return errExpired
	}
	if t.db.node(fromID) == nil {
		// No bond exists, we don't process the packet. This prevents
		// an attack vector where the discovery protocol could be used
		// to amplify traffic in a DDOS attack. A malicious actor
		// would send a findnode request with the IP address and UDP
		// port of the target as the source address. The recipient of
		// the findnode packet would then send a neighbors packet
		// (which is a much bigger packet than findnode) to the victim.
		return errUnknownNode
	}
	closest := t.closest(req.Target).Slice()

	p := neighbors{Expiration: uint64(time.Now().Add(expiration).Unix())}

	// Send neighbors in chunks with at most maxNeighbors per packet
	// to stay below the 1280 byte limit.
	for i, n := range closest {
		p.Nodes = append(p.Nodes, nodeToRPC(n))
		if len(p.Nodes) == maxNeighbors || i == len(closest)-1 {
			t.send(from, neighborsPacket, p)
			p.Nodes = p.Nodes[:0]
		}
	}
	return nil
}

func (req *neighbors) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	if expired(req.Expiration) {
		return errExpired
	}
	if !t.handleReply(fromID, neighborsPacket, req) {
		return errUnsolicitedReply
	}
	return nil
}

func expired(ts uint64) bool {
	return time.Unix(int64(ts), 0).Before(time.Now())
}

func isReserved(ip net.IP) bool {
	reserved := [][2]net.IP{
		Ipv4ReservedRangeThis,
		Ipv4ReservedRangePrivateNetwork,
		ipv4ReservedRangeProviderSubscriber,
		Ipv4ReservedRangeLoopback,
		ipv4ReservedRangeLinkLocal,
		ipv4ReservedRangeLocalPrivate1,
		ipv4ReservedRangeSpecialPurpose,
		ipv4ReservedRangeTestNet1,
		ipv4ReservedRange6to4,
		Ipv4ReservedRangeLocalPrivate2,
		ipv4ReservedRangeSubnets,
		ipv4ReservedRangeTestNet2,
		ipv4ReservedRangeTestNet3,
		ipv4ReservedRangeMulticast,
		ipv4ReservedRangeFuture,
		ipv4ReservedRangeLimitedBroadcast,
		ipv6ReservedRangeUnspecified,
		Ipv6ReservedRangeLoopback,
		ipv6ReservedRangeDocumentation,
		ipv6ReservedRange6to4,
		ipv6ReservedRangeUniqueLocal,
		ipv6ReservedRangeLinkLocal,
		ipv6ReservedRangeMulticast,
	}
	for _, r := range reserved {
		isReserved, err := IpBetween(r[0], r[1], ip)
		if err != nil {
			glog.V(logger.Debug).Infof("error checking if ip reserved: %v", err)
			return true
		}
		if isReserved {
			return true
		}
	}
	return false
}

// IpBetween determines if a given ip is between two others (inclusive)
// > https://stackoverflow.com/questions/19882961/go-golang-check-ip-address-in-range
func IpBetween(from net.IP, to net.IP, test net.IP) (bool, error) {
	if from == nil || to == nil || test == nil {
		return false, errInvalidIp
	}

	from16 := from.To16()
	to16 := to.To16()
	test16 := test.To16()
	if from16 == nil || to16 == nil || test16 == nil {
		return false, errors.New("ip did not convert to a 16 byte")
	}

	if bytes.Compare(test16, from16) >= 0 && bytes.Compare(test16, to16) <= 0 {
		return true, nil
	}
	return false, nil
}
