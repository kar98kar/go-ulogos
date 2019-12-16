package downloader

import (
	"github.com/kar98kar/go-ulogos/core"
)

type InsertChainEvent struct {
	core.ChainInsertEvent
}

type InsertReceiptChainEvent struct {
	core.ReceiptChainInsertEvent
	Pivot bool
}

type InsertHeaderChainEvent struct {
	core.HeaderChainInsertEvent
}
