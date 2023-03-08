from dataclasses import dataclass

from zklink_sdk.types import ChainId


@dataclass
class Network:
    zklink_url: str


testnet = Network(zklink_url="https://aws-gw-v2.zk.link/rpc")
devnet = Network(zklink_url="https://dev-gw-v1.zk.link/")
