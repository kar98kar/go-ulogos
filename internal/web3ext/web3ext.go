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

// package web3ext contains geth specific web3.js extensions.
package web3ext

var Modules = map[string]string{
	"admin":    Admin_JS,
	"debug":    Debug_JS,
	"eth":      Eth_JS,
	"miner":    Miner_JS,
	"net":      Net_JS,
	"personal": Personal_JS,
	"rpc":      RPC_JS,
	"shh":      Shh_JS,
	"txpool":   TxPool_JS,
	"geth":     Geth_JS,
}

const Admin_JS = `
web3._extend({
	property: 'admin',
	methods:
	[
		new web3._extend.Method({
			name: 'addPeer',
			call: 'admin_addPeer',
			params: 1
		}),
		new web3._extend.Method({
			name: 'exportChain',
			call: 'admin_exportChain',
			params: 1,
			inputFormatter: [null]
		}),
		new web3._extend.Method({
			name: 'importChain',
			call: 'admin_importChain',
			params: 1
		}),
		new web3._extend.Method({
			name: 'sleepBlocks',
			call: 'admin_sleepBlocks',
			params: 2
		}),
		new web3._extend.Method({
			name: 'setSolc',
			call: 'admin_setSolc',
			params: 1
		}),
		new web3._extend.Method({
			name: 'startRPC',
			call: 'admin_startRPC',
			params: 4,
			inputFormatter: [null, null, null, null]
		}),
		new web3._extend.Method({
			name: 'stopRPC',
			call: 'admin_stopRPC'
		}),
		new web3._extend.Method({
			name: 'startWS',
			call: 'admin_startWS',
			params: 4,
			inputFormatter: [null, null, null, null]
		}),
		new web3._extend.Method({
			name: 'stopWS',
			call: 'admin_stopWS'
		}),
		new web3._extend.Method({
			name: 'setGlobalRegistrar',
			call: 'admin_setGlobalRegistrar',
			params: 2
		}),
		new web3._extend.Method({
			name: 'setHashReg',
			call: 'admin_setHashReg',
			params: 2
		}),
		new web3._extend.Method({
			name: 'setUrlHint',
			call: 'admin_setUrlHint',
			params: 2
		}),
		new web3._extend.Method({
			name: 'saveInfo',
			call: 'admin_saveInfo',
			params: 2
		}),
		new web3._extend.Method({
			name: 'register',
			call: 'admin_register',
			params: 3
		}),
		new web3._extend.Method({
			name: 'registerUrl',
			call: 'admin_registerUrl',
			params: 3
		}),
		new web3._extend.Method({
			name: 'startNatSpec',
			call: 'admin_startNatSpec',
			params: 0
		}),
		new web3._extend.Method({
			name: 'stopNatSpec',
			call: 'admin_stopNatSpec',
			params: 0
		}),
		new web3._extend.Method({
			name: 'getContractInfo',
			call: 'admin_getContractInfo',
			params: 1
		}),
		new web3._extend.Method({
			name: 'httpGet',
			call: 'admin_httpGet',
			params: 2
		})
	],
	properties:
	[
		new web3._extend.Property({
			name: 'nodeInfo',
			getter: 'admin_nodeInfo'
		}),
		new web3._extend.Property({
			name: 'peers',
			getter: 'admin_peers'
		}),
		new web3._extend.Property({
			name: 'datadir',
			getter: 'admin_datadir'
		})
	]
});
`

const Geth_JS = `
web3._extend({
	property: 'geth',
	methods:
	[
		new web3._extend.Method({
			name: 'getAddressTransactions',
			call: 'geth_getAddressTransactions',
			params: 8,
			inputFormatter: [web3._extend.formatters.inputAddressFormatter, null, web3._extend.formatters.inputDefaultBlockNumberFormatter, null, null, null, null, null]
		}),
		new web3._extend.Method({
			name: 'getTransactionsByAddress',
			call: 'geth_getTransactionsByAddress',
			params: 8,
			inputFormatter: [web3._extend.formatters.inputAddressFormatter, null, web3._extend.formatters.inputDefaultBlockNumberFormatter, null, null, null, null, null]
		}),
		new web3._extend.Method({
			name: 'buildATXI',
			call: 'geth_buildATXI',
			params: 3,
			inputFormatter: [web3._extend.formatters.inputDefaultBlockNumberFormatter, web3._extend.formatters.inputDefaultBlockNumberFormatter, null]
		}),
		new web3._extend.Method({
			name: 'getATXIBuildStatus',
			call: 'geth_getATXIBuildStatus',
			params: 0,
		})
	],
	properties: []
});
`

const Debug_JS = `
web3._extend({
	property: 'debug',
	methods:
	[
		new web3._extend.Method({
			name: 'printBlock',
			call: 'debug_printBlock',
			params: 1
		}),
		new web3._extend.Method({
			name: 'getBlockRlp',
			call: 'debug_getBlockRlp',
			params: 1
		}),
		new web3._extend.Method({
			name: 'setHead',
			call: 'debug_setHead',
			params: 1
		}),
		new web3._extend.Method({
			name: 'seedHash',
			call: 'debug_seedHash',
			params: 1
		}),
		new web3._extend.Method({
			name: 'dumpBlock',
			call: 'debug_dumpBlock',
			params: 1
		}),
		new web3._extend.Method({
			name: 'metrics',
			call: 'debug_metrics',
			params: 1,
			inputFormatter: [web3._extend.formatters.inputOptionalBoolFormatter]
		}),
		new web3._extend.Method({
			name: 'verbosity',
			call: 'debug_verbosity',
			params: 1,
			inputFormatter: [web3._extend.formatters.inputOptionalNumberFormatter]
		}),
		new web3._extend.Method({
			name: 'vmodule',
			call: 'debug_vmodule',
			params: 1,
			inputFormatter: [web3._extend.formatters.inputOptionalStringFormatter]
		}),
		new web3._extend.Method({
			name: 'traceTransaction',
			call: 'debug_traceTransaction',
			params: 1
		}),
		new web3._extend.Method({
			name: 'accountExist',
			call: 'debug_accountExist',
			params: 2
		})
	],
	properties: []
});
`

const Eth_JS = `
web3._extend({
	property: 'eth',
	methods:
	[
		new web3._extend.Method({
			name: 'sign',
			call: 'eth_sign',
			params: 2,
			inputFormatter: [web3._extend.formatters.inputAddressFormatter, null]
		}),
		new web3._extend.Method({
			name: 'resend',
			call: 'eth_resend',
			params: 3,
			inputFormatter: [web3._extend.formatters.inputTransactionFormatter, web3._extend.utils.fromDecimal, web3._extend.utils.fromDecimal]
		}),
		new web3._extend.Method({
			name: 'getNatSpec',
			call: 'eth_getNatSpec',
			params: 1,
			inputFormatter: [web3._extend.formatters.inputTransactionFormatter]
		}),
		new web3._extend.Method({
			name: 'signTransaction',
			call: 'eth_signTransaction',
			params: 1,
			inputFormatter: [web3._extend.formatters.inputTransactionFormatter]
		}),
		new web3._extend.Method({
			name: 'submitTransaction',
			call: 'eth_submitTransaction',
			params: 1,
			inputFormatter: [web3._extend.formatters.inputTransactionFormatter]
		}),
		new web3._extend.Method({
			name: 'chainId',
			call: 'eth_chainId',
			params: 0
		})
	],
	properties:
	[
		new web3._extend.Property({
			name: 'pendingTransactions',
			getter: 'eth_pendingTransactions',
			outputFormatter: function(txs) {
				var formatted = [];
				for (var i = 0; i < txs.length; i++) {
					formatted.push(web3._extend.formatters.outputTransactionFormatter(txs[i]));
					formatted[i].blockHash = null;
				}
				return formatted;
			}
		})
	]
});
`

const Miner_JS = `
web3._extend({
	property: 'miner',
	methods:
	[
		new web3._extend.Method({
			name: 'start',
			call: 'miner_start',
			params: 1,
			inputFormatter: [null]
		}),
		new web3._extend.Method({
			name: 'stop',
			call: 'miner_stop'
		}),
		new web3._extend.Method({
			name: 'setEtherbase',
			call: 'miner_setEtherbase',
			params: 1,
			inputFormatter: [web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'setExtra',
			call: 'miner_setExtra',
			params: 1
		}),
		new web3._extend.Method({
			name: 'setGasPrice',
			call: 'miner_setGasPrice',
			params: 1,
			inputFormatter: [web3._extend.utils.fromDecimal]
		}),
		new web3._extend.Method({
			name: 'startAutoDAG',
			call: 'miner_startAutoDAG',
			params: 0
		}),
		new web3._extend.Method({
			name: 'stopAutoDAG',
			call: 'miner_stopAutoDAG',
			params: 0
		}),
		new web3._extend.Method({
			name: 'makeDAG',
			call: 'miner_makeDAG',
			params: 1,
			inputFormatter: [web3._extend.formatters.inputDefaultBlockNumberFormatter]
		})
	],
	properties: []
});
`

const Net_JS = `
web3._extend({
	property: 'net',
	methods: [],
	properties:
	[
		new web3._extend.Property({
			name: 'version',
			getter: 'net_version'
		})
	]
});
`

const Personal_JS = `
web3._extend({
	property: 'personal',
	methods:
	[
		new web3._extend.Method({
			name: 'importRawKey',
			call: 'personal_importRawKey',
			params: 2
		}),
		new web3._extend.Method({
			name: 'ImportWIFKey',
			call: 'personal_ImportWIFKey',
			params: 2
		}),
		new web3._extend.Method({
			name: 'signAndSendTransaction',
			call: 'personal_signAndSendTransaction',
			params: 2,
			inputFormatter: [web3._extend.formatters.inputTransactionFormatter, null]
		}),
		new web3._extend.Method({
			name: 'sendTransaction',
			call: 'personal_sendTransaction',
			params: 2,
			inputFormatter: [web3._extend.formatters.inputTransactionFormatter, null]
		}),
		new web3._extend.Method({
			name: 'ecRecover',
			call: 'personal_ecRecover',
			params: 2,
			inputFormatter: [null, null]
		})
	]
});
`

const RPC_JS = `
web3._extend({
	property: 'rpc',
	methods: [],
	properties:
	[
		new web3._extend.Property({
			name: 'modules',
			getter: 'rpc_modules'
		})
	]
});
`

const Shh_JS = `
web3._extend({
	property: 'shh',
	methods: [],
	properties:
	[
		new web3._extend.Property({
			name: 'version',
			getter: 'shh_version',
			outputFormatter: web3._extend.utils.toDecimal
		})
	]
});
`

const TxPool_JS = `
web3._extend({
	property: 'txpool',
	methods: [],
	properties:
	[
		new web3._extend.Property({
			name: 'content',
			getter: 'txpool_content'
		}),
		new web3._extend.Property({
			name: 'inspect',
			getter: 'txpool_inspect'
		}),
		new web3._extend.Property({
			name: 'status',
			getter: 'txpool_status',
			outputFormatter: function(status) {
				status.pending = web3._extend.utils.toDecimal(status.pending);
				status.queued = web3._extend.utils.toDecimal(status.queued);
				return status;
			}
		})
	]
});
`
