package util

type SubAuxTask struct {
	SubchainID []int `json:"subchainid"`
	AuxTask
}

type AuxTask struct {
	Hash              string `json:"hash"`
	Chainid           int    `json:"chainid"`
	Previousblockhash string `json:"previousblockhash"`
	Coinbasevalue     int    `json:"coinbasevalue"`
	Bits              string `json:"bits"`
	Height            int    `json:"height"`
	Target            string `json:"target"`
}
