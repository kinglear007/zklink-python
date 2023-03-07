from dataclasses import dataclass

from zklink_sdk.types import ChainId


@dataclass
class Network:
    zklink_url: str
    # chain_id: ChainId


# rinkeby = Network(zklink_url="https://rinkeby-api.zksync.io/jsrpc", chain_id=ChainId.RINKEBY)
# ropsten = Network(zklink_url="https://ropsten-api.zksync.io/jsrpc", chain_id=ChainId.ROPSTEN)
# mainnet = Network(zklink_url="https://api.zksync.io/jsrpc", chain_id=ChainId.MAINNET)
# goerli = Network(zklink_url="https://goerli-api.zksync.io/jsrpc", chain_id=ChainId.GOERLI)
# sepolia = Network(zklink_url="https://sepolia-api.zksync.io/jsrpc", chain_id=ChainId.SEPOLIA)
# localhost = Network(zklink_url="http://localhost:3030/jsrpc", chain_id=ChainId.LOCALHOST)


testnet = Network(zklink_url="https://aws-gw-v2.zk.link/rpc")
