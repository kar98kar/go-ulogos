// Copyright 2014 The go-ethereum Authors
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

package core

import (
	"fmt"
	"math/big"

	"github.com/kar98kar/go-ulogos/common"
	"github.com/kar98kar/go-ulogos/core/vm"
	"github.com/kar98kar/go-ulogos/logger"
	"github.com/kar98kar/go-ulogos/logger/glog"
)

var (
	TxGas                 = big.NewInt(21000) // Per transaction not creating a contract. NOTE: Not payable on data of calls between transactions.
	TxGasContractCreation = big.NewInt(53000) // Per transaction that creates a contract. NOTE: Not payable on data of calls between transactions.
	TxDataZeroGas         = big.NewInt(4)     // Per byte of data attached to a transaction that equals zero. NOTE: Not payable on data of calls between transactions.
	TxDataNonZeroGas      = big.NewInt(68)    // Per byte of data attached to a transaction that is not equal to zero. NOTE: Not payable on data of calls between transactions.
)

/*
The State Transitioning Model

A state transition is a change made when a transaction is applied to the current world state
The state transitioning model does all all the necessary work to work out a valid new state root.

1) Nonce handling
2) Pre pay gas
3) Create a new state object if the recipient is \0*32
4) Value transfer
== If contract creation ==
  4a) Attempt to run transaction data
  4b) If valid, use result as code for the new state object
== end ==
5) Run Script section
6) Derive new state root
*/
type StateTransition struct {
	gp            *GasPool
	msg           Message
	gas, gasPrice *big.Int
	initialGas    *big.Int
	value         *big.Int
	data          []byte
	state         vm.Database

	env vm.Environment
}

// Message represents a message sent to a contract.
type Message interface {
	From() (common.Address, error)
	To() *common.Address

	GasPrice() *big.Int
	Gas() *big.Int
	Value() *big.Int

	Nonce() uint64
	Data() []byte
}

func MessageCreatesContract(msg Message) bool {
	return msg.To() == nil
}

// IntrinsicGas computes the 'intrinsic gas' for a message
// with the given data.
func IntrinsicGas(data []byte, contractCreation, homestead bool) *big.Int {
	igas := new(big.Int)
	if contractCreation && homestead {
		igas.Set(TxGasContractCreation)
	} else {
		igas.Set(TxGas)
	}
	if len(data) > 0 {
		var nz int64
		for _, byt := range data {
			if byt != 0 {
				nz++
			}
		}
		m := big.NewInt(nz)
		m.Mul(m, TxDataNonZeroGas)
		igas.Add(igas, m)
		m.SetInt64(int64(len(data)) - nz)
		m.Mul(m, TxDataZeroGas)
		igas.Add(igas, m)
	}
	return igas
}

// NewStateTransition initialises and returns a new state transition object.
func NewStateTransition(env vm.Environment, msg Message, gp *GasPool) *StateTransition {
	return &StateTransition{
		gp:         gp,
		env:        env,
		msg:        msg,
		gas:        new(big.Int),
		gasPrice:   msg.GasPrice(),
		initialGas: new(big.Int),
		value:      msg.Value(),
		data:       msg.Data(),
		state:      env.Db(),
	}
}

// ApplyMessage computes the new state by applying the given message
// against the old state within the environment.
//
// ApplyMessage returns the bytes returned by any EVM execution (if it took place),
// the gas used (which includes gas refunds) and an error if it failed. An error always
// indicates a core error meaning that the message would always fail for that particular
// state and would never be accepted within a block.
func ApplyMessage(env vm.Environment, msg Message, gp *GasPool) ([]byte, *big.Int, bool, error) {
	st := NewStateTransition(env, msg, gp)

	ret, gasUsed, failed, err := st.TransitionDb()
	return ret, gasUsed, failed, err
}

func (self *StateTransition) from() (vm.Account, error) {
	var (
		f   common.Address
		err error
	)
	f, err = self.msg.From()
	if err != nil {
		return nil, err
	}
	if !self.state.Exist(f) {
		return self.state.CreateAccount(f), nil
	}
	return self.state.GetAccount(f), nil
}

func (self *StateTransition) to() vm.Account {
	if self.msg == nil {
		return nil
	}
	to := self.msg.To()
	if to == nil {
		return nil // contract creation
	}

	if !self.state.Exist(*to) {
		return self.state.CreateAccount(*to)
	}
	return self.state.GetAccount(*to)
}

func (self *StateTransition) useGas(amount *big.Int) error {
	if self.gas.Cmp(amount) < 0 {
		return vm.OutOfGasError
	}
	self.gas.Sub(self.gas, amount)

	return nil
}

func (self *StateTransition) addGas(amount *big.Int) {
	self.gas.Add(self.gas, amount)
}

func (self *StateTransition) buyGas() error {
	mgas := self.msg.Gas()
	mgval := new(big.Int).Mul(mgas, self.gasPrice)

	sender, err := self.from()
	if err != nil {
		return err
	}
	if sender.Balance().Cmp(mgval) < 0 {
		return fmt.Errorf("insufficient ETH for gas (%x). Req %v, has %v", sender.Address().Bytes()[:4], mgval, sender.Balance())
	}
	if err = self.gp.SubGas(mgas); err != nil {
		return err
	}
	self.addGas(mgas)
	self.initialGas.Set(mgas)
	sender.SubBalance(mgval)
	return nil
}

func (self *StateTransition) preCheck() (err error) {
	msg := self.msg
	sender, err := self.from()
	if err != nil {
		return err
	}

	// Make sure this transaction's nonce is correct
	if n := self.state.GetNonce(sender.Address()); n != msg.Nonce() {
		return NonceError(msg.Nonce(), n)
	}

	// Pre-pay gas
	if err = self.buyGas(); err != nil {
		if IsGasLimitErr(err) {
			return err
		}
		return InvalidTxError(err)
	}

	return nil
}

// TransitionDb will move the state by applying the message against the given environment.
func (self *StateTransition) TransitionDb() (ret []byte, gas *big.Int, failed bool, err error) {
	if err = self.preCheck(); err != nil {
		return
	}
	msg := self.msg
	sender, _ := self.from() // err checked in preCheck

	homestead := self.env.RuleSet().IsHomestead(self.env.BlockNumber())
	contractCreation := MessageCreatesContract(msg)
	// Pay intrinsic gas
	if err = self.useGas(IntrinsicGas(self.data, contractCreation, homestead)); err != nil {
		return nil, nil, false, InvalidTxError(err)
	}

	vmenv := self.env
	//var addr common.Address
	var vmerr error
	if contractCreation {
		ret, _, vmerr = vmenv.Create(sender, self.data, self.gas, self.gasPrice, self.value)
		if homestead && vmerr == vm.CodeStoreOutOfGasError {
			self.gas = big.NewInt(0)
		}

		if vmerr != nil {
			glog.V(logger.Core).Infoln("VM create err:", vmerr)
		}
	} else {
		// Increment the nonce for the next transaction
		self.state.SetNonce(sender.Address(), self.state.GetNonce(sender.Address())+1)
		ret, vmerr = vmenv.Call(sender, self.to().Address(), self.data, self.gas, self.gasPrice, self.value)
		if vmerr != nil {
			glog.V(logger.Core).Infoln("VM call err:", vmerr)
		}
	}

	if vmerr != nil && IsValueTransferErr(vmerr) {
		// if the vmerr was a value transfer error, return immediately
		// transaction receipt status will be set to TxSuccess
		return nil, nil, false, InvalidTxError(vmerr)
	}

	self.refundGas()
	self.state.AddBalance(self.env.Coinbase(), new(big.Int).Mul(self.gasUsed(), self.gasPrice))

	return ret, self.gasUsed(), vmerr != nil, err
}

func (self *StateTransition) refundGas() {
	// Return eth for remaining gas to the sender account,
	// exchanged at the original rate.
	sender, _ := self.from() // err already checked
	remaining := new(big.Int).Mul(self.gas, self.gasPrice)
	sender.AddBalance(remaining)

	// Apply refund counter, capped to half of the used gas.
	uhalf := remaining.Div(self.gasUsed(), common.Big2)
	refund := common.BigMin(uhalf, self.state.GetRefund())
	self.gas.Add(self.gas, refund)
	self.state.AddBalance(sender.Address(), refund.Mul(refund, self.gasPrice))
	// Also return remaining gas to the block gas counter so it is
	// available for the next transaction.
	self.gp.AddGas(self.gas)
}

func (self *StateTransition) gasUsed() *big.Int {
	return new(big.Int).Sub(self.initialGas, self.gas)
}
