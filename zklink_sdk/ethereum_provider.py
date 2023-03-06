from decimal import Decimal
from typing import Optional

from web3 import Web3

from zklink_sdk.types import Token
from zklink_sdk.zklink import ERC20Contract, ZkLink

DEFAULT_AUTH_FACTS = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


class EthereumProvider:
    def __init__(self, web3: Web3, zklink: ZkLink):
        self.web3 = web3
        self.zklink = zklink

    async def approve_deposit(self, token: Token, limit: Decimal):
        contract = ERC20Contract(self.web3, self.zklink.contract_address, token.address,
                                 self.zklink.account)
        return contract.approve_deposit(token.from_decimal(limit))

    async def deposit(self, token: Token, amount: Decimal, address: str):
        if token.is_eth():
            return self.zklink.deposit_eth(address, token.from_decimal(amount))
        else:
            return self.zklink.deposit_erc20(token.address, address, token.from_decimal(amount))

    async def full_exit(self, token: Token, account_id: int):
        return self.zklink.full_exit(account_id, token.address)

    async def full_exit_nft(self, nft: Token, account_id: int):
        return self.zklink.full_exit_nft(account_id, nft.id)

    async def set_auth_pubkey_hash(self, pubkey_hash: bytes, nonce: int):
        return self.zklink.set_auth_pub_key_hash(pubkey_hash, nonce)

    async def is_deposit_approved(self, token: Token, threshold: int) -> bool:
        contract = ERC20Contract(self.web3, self.zklink.contract_address, token.address,
                                 self.zklink.account)
        return contract.is_deposit_approved(threshold)

    async def is_onchain_auth_pubkey_hash_set(self, nonce: int) -> bool:
        auth_facts = self.zklink.auth_facts(self.zklink.account.address, nonce)
        return auth_facts != DEFAULT_AUTH_FACTS
