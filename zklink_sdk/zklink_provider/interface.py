from abc import ABC, abstractmethod
from decimal import Decimal
from typing import List, Optional, Union
from zklink_sdk.transport import JsonRPCTransport
from zklink_sdk.types import (AccountState, ContractAddress, EncodedTx, Fee, Token,
                              Tokens, TransactionDetails, TransactionWithSignature,
                              TransactionWithOptionalSignature,
                              TxEthSignature, SubmitSignature,
                              ChangePubKey, ForcedExit, Withdraw, Transfer)
from zklink_sdk.zklink_provider.types import FeeTxType
from zklink_sdk.zklink_provider.transaction import Transaction

__all__ = ['ZkLinkProviderInterface']


class ZkLinkProviderInterface(ABC):
    def __init__(self, provider: JsonRPCTransport):
        self.provider = provider

    @abstractmethod
    async def send_transaction(self, tx: EncodedTx, signature: Optional[TxEthSignature],
                               submitter_signature: Optional[SubmitSignature] = None) -> Transaction:
        raise NotImplementedError

    @abstractmethod
    async def get_support_tokens(self) -> Tokens:
        raise NotImplementedError

    @abstractmethod
    async def get_contract_address(self, chain_id: int) -> ContractAddress:
        raise NotImplementedError

    @abstractmethod
    async def get_account(self, address: str) -> AccountState:
        raise NotImplementedError

    @abstractmethod
    async def get_account_nonce(self, address: str) -> int:
        raise NotImplementedError

    @abstractmethod
    async def get_account_balances(self, account_id: int, sub_account_id: int):
        raise NotImplementedError

    @abstractmethod
    async def get_transaction_by_hash(self, tx_hash: str, include_update: bool) -> TransactionDetails:
        raise NotImplementedError

    @abstractmethod
    async def estimate_transaction_fee(self, tx: Union[ChangePubKey, ForcedExit, Withdraw, Transfer]) -> Fee:
        raise NotImplementedError
