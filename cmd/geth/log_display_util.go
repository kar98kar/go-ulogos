package main

import (
	"time"

	"github.com/kar98kar/go-ulogos/eth"
	"github.com/kar98kar/go-ulogos/eth/downloader"
	"gopkg.in/urfave/cli.v1"
)

//go:generate stringer -type=logEventType
type logEventType int

const (
	logEventCoreChainInsert logEventType = iota
	logEventCoreChainInsertSide
	logEventCoreHeaderChainInsert
	logEventCoreReceiptChainInsert
	logEventCoreMinedBlock
	logEventDownloaderStart
	logEventDownloaderDone
	logEventDownloaderFailed
	logEventDownloaderInsertChain
	logEventDownloaderInsertReceiptChain
	logEventDownloaderInsertHeaderChain
	logEventFetcherInsert
	logEventPMHandlerAdd
	logEventPMHandlerRemove
	logEventInterval
	logEventBefore
	logEventAfter
)

// Global bookmark vars.
// These are accessible globally to allow inter-communication between display system event handlers.
// Note: since these may be read/modified from concurrent operations (eg. handler fns), these variables are NOT thread safe.
// In the case that a logging operation requires thread safety, use externally implemented locking.
var currentMode = lsModeDiscover
var currentBlockNumber uint64
var chainEventLastSent time.Time

// updateLogStatusModeHandler implements the displayEventHandlerFn signature interface
// It is a convenience fn to update the global 'currentMode' var.
// Typically it should be called from downloader events, and uses the 'getLogStatusMode' logic.
func updateLogStatusModeHandler(ctx *cli.Context, e *eth.Ethereum, evData interface{}, tickerInterval time.Duration) {
	currentMode = getLogStatusMode(e)
}

// getLogStatusMode gets the "mode" for the ethereum node at any given time.
// It is used to set the global bookmark variable, and influences formatting logic.
func getLogStatusMode(e *eth.Ethereum) lsMode {
	if e.Downloader().Synchronising() {
		switch e.Downloader().GetMode() {
		case downloader.FullSync:
			return lsModeFullSync
		case downloader.FastSync:
			return lsModeFastSync
		}
	}
	if e.Downloader().GetPeers().Len() == 0 {
		return lsModeDiscover
	}
	_, current, height, _, _ := e.Downloader().Progress() // origin, current, height, pulled, known
	if height > 0 && height < current {
		return lsModeImport
	}
	return lsModeDiscover
}
