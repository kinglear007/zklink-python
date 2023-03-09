from abc import ABC, abstractmethod
from decimal import Decimal
from typing import List, Optional, Union
from zklink_sdk.transport import JsonRPCTransport
from zklink_sdk.types import (AccountState, ContractAddress, EncodedTx, Fee, Token,
                              TokenLike, Tokens, TransactionDetails, TransactionWithSignature,
                              TransactionWithOptionalSignature,
                              TxEthSignature, SubmitSignature)
from zklink_sdk.zklink_provider.types import FeeTxType
from zklink_sdk.zklink_provider.transaction import Transaction

__all__ = ['ZkLinkProviderInterface']


class ZkLinkProviderInterface(ABC):
    def __init__(self, provider: JsonRPCTransport):
        self.provider = provider

    @abstractmethod
    async def submit_tx(self, tx: EncodedTx, signature: Optional[TxEthSignature],
                        submitter_signature: Optional[SubmitSignature] = None) -> Transaction:
        raise NotImplementedError

    @abstractmethod
    async def get_support_tokens(self) -> Tokens:
        raise NotImplementedError

    @abstractmethod
    async def get_contract_address(self, chain_id: int) -> ContractAddress:
        raise NotImplementedError

    @abstractmethod
    async def get_state(self, address: str) -> AccountState:
        raise NotImplementedError

    @abstractmethod
    async def get_account_nonce(self, address: str) -> int:
        raise NotImplementedError

    @abstractmethod
    async def get_tx_receipt(self, address: str) -> TransactionDetails:
        raise NotImplementedError

    @abstractmethod
    async def get_transaction_fee(self, tx_type: FeeTxType, address: str,
                                  token_like: TokenLike) -> Fee:
        raise NotImplementedError
