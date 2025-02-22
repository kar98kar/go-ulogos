// Copyright 2015 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

// gethrpctest is a command to run the external RPC tests.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"

	"path/filepath"

	"github.com/kar98kar/go-ulogos/accounts"
	"github.com/kar98kar/go-ulogos/common"
	"github.com/kar98kar/go-ulogos/core"
	"github.com/kar98kar/go-ulogos/crypto"
	"github.com/kar98kar/go-ulogos/eth"
	"github.com/kar98kar/go-ulogos/ethdb"
	"github.com/kar98kar/go-ulogos/logger/glog"
	"github.com/kar98kar/go-ulogos/node"
	"github.com/kar98kar/go-ulogos/tests"
	"github.com/kar98kar/go-ulogos/whisper"
)

// Version is the application revision identifier. It can be set with the linker
// as in: go build -ldflags "-X main.Version="`git describe --tags`
var Version = "unknown"

var (
	testFile    = flag.String("json", "", "Path to the .json test file to load")
	testName    = flag.String("test", "", "Name of the test from the .json file to run")
	testKey     = flag.String("key", defaultTestKey, "Private key of a test account to inject")
	versionFlag = flag.Bool("version", false, "Prints the revision identifier and exit immediatily.")
)

const defaultTestKey = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291"

func main() {
	flag.Parse()

	if *versionFlag {
		fmt.Println("gethrpctest version", Version)
		os.Exit(0)
	}

	// Enable logging errors, we really do want to see those
	glog.SetV(2)
	glog.SetToStderr(true)

	// Load the test suite to run the RPC against
	tests, err := tests.LoadBlockTests(*testFile)
	if err != nil {
		log.Fatalf("Failed to load test suite: %v", err)
	}
	test, found := tests[*testName]
	if !found {
		log.Fatalf("Requested test (%s) not found within suite", *testName)
	}
	// Create the protocol stack to run the test with
	keydir, err := ioutil.TempDir("", "")
	if err != nil {
		log.Fatalf("Failed to create temporary keystore directory: %v", err)
	}
	defer os.RemoveAll(keydir)

	stack, err := MakeSystemNode(keydir, *testKey, test)
	if err != nil {
		log.Fatalf("Failed to assemble test stack: %v", err)
	}
	if err := stack.Start(); err != nil {
		log.Fatalf("Failed to start test node: %v", err)
	}
	defer stack.Stop()

	log.Println("Test node started...")

	// Make sure the tests contained within the suite pass
	if err := RunTest(stack, test); err != nil {
		log.Fatalf("Failed to run the pre-configured test: %v", err)
	}
	log.Println("Initial test suite passed...")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
}

// MakeSystemNode configures a protocol stack for the RPC tests based on a given
// keystore path and initial pre-state.
func MakeSystemNode(keydir string, privkey string, test *tests.BlockTest) (*node.Node, error) {
	// Create a networkless protocol stack
	stack, err := node.New(&node.Config{
		IPCPath:     node.DefaultIPCEndpoint(filepath.Join(common.DefaultDataDir(), "mainnet")),
		HTTPHost:    common.DefaultHTTPHost,
		HTTPPort:    common.DefaultHTTPPort,
		HTTPModules: []string{"admin", "db", "eth", "debug", "miner", "net", "shh", "txpool", "personal", "web3"},
		WSHost:      common.DefaultWSHost,
		WSPort:      common.DefaultWSPort,
		WSModules:   []string{"admin", "db", "eth", "debug", "miner", "net", "shh", "txpool", "personal", "web3"},
		NoDiscovery: true,
	})
	if err != nil {
		return nil, err
	}
	// Create the keystore and inject an unlocked account if requested
	accman, err := accounts.NewManager(keydir, accounts.LightScryptN, accounts.LightScryptP, false)
	if err != nil {
		return nil, err
	}

	if len(privkey) > 0 {
		key, err := crypto.HexToECDSA(privkey)
		if err != nil {
			return nil, err
		}
		a, err := accman.ImportECDSA(key, "")
		if err != nil {
			return nil, err
		}
		if err := accman.Unlock(a, ""); err != nil {
			return nil, err
		}
	}
	// Initialize and register the Ethereum protocol
	db, _ := ethdb.NewMemDatabase()
	if _, err := test.InsertPreState(db); err != nil {
		return nil, err
	}
	ethConf := &eth.Config{
		TestGenesisState: db,
		TestGenesisBlock: test.Genesis,
		ChainConfig:      core.DefaultConfigMainnet.ChainConfig,
		AccountManager:   accman,
	}
	if err := stack.Register(func(ctx *node.ServiceContext) (node.Service, error) { return eth.New(ctx, ethConf) }); err != nil {
		return nil, err
	}
	// Initialize and register the Whisper protocol
	if err := stack.Register(func(*node.ServiceContext) (node.Service, error) { return whisper.New(), nil }); err != nil {
		return nil, err
	}
	return stack, nil
}

// RunTest executes the specified test against an already pre-configured protocol
// stack to ensure basic checks pass before running RPC tests.
func RunTest(stack *node.Node, test *tests.BlockTest) error {
	var ethereum *eth.Ethereum
	stack.Service(&ethereum)
	blockchain := ethereum.BlockChain()

	// Process the blocks and verify the imported headers
	blocks, err := test.TryBlocksInsert(blockchain)
	if err != nil {
		return err
	}
	if err := test.ValidateImportedHeaders(blockchain, blocks); err != nil {
		return err
	}
	// Retrieve the assembled state and validate it
	stateDb, err := blockchain.State()
	if err != nil {
		return err
	}
	if err := test.ValidatePostState(stateDb); err != nil {
		return err
	}
	return nil
}
