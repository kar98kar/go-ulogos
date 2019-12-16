package fetcher

import "github.com/kar98kar/go-ulogos/core/types"

type FetcherInsertBlockEvent struct {
	Peer  string
	Block *types.Block
}
