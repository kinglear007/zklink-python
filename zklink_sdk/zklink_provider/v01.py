from dataclasses import asdict
from decimal import Decimal
from typing import List, Optional, Union
from web3 import Web3

from zklink_sdk.types import (AccountState, ContractAddress, EncodedTx, Fee, Token,
                              TokenLike, Tokens, TransactionDetails, TransactionWithSignature,
                              TransactionWithOptionalSignature,
                              TxEthSignature, SubmitSignature)
from zklink_sdk.zklink_provider.error import AccountDoesNotExist
from zklink_sdk.zklink_provider.interface import ZkLinkProviderInterface
from zklink_sdk.zklink_provider.types import FeeTxType
from zklink_sdk.zklink_provider.transaction import Transaction

__all__ = ['ZkLinkProviderV01']


class ZkLinkProviderV01(ZkLinkProviderInterface):
    async def submit_tx(self, tx: EncodedTx, signature: Optional[TxEthSignature],
                        submitter_signature: Optional[SubmitSignature] = None) -> Transaction:
        signature = signature.dict() if signature is not None else None
        submitter_signature = submitter_signature.signature if submitter_signature is not None else None
        trans_id = await self.provider.request("tx_submit",
                                               [tx.dict(), signature, submitter_signature])
        return Transaction.build_transaction(self, trans_id)

    async def get_support_tokens(self) -> Tokens:
        data = await self.provider.request("getSupportTokens", None)
        tokens = []
        for token in data.values():
            for chain in token['chains']:
                t = Token(address=Web3.toChecksumAddress(chain['address']),
                          chain_id=chain['chainId'],
                          decimals=chain['decimals'],
                          id=token['id'],
                          symbol=token['symbol'])
                tokens.append(t)
        return Tokens(tokens=tokens)

    async def get_contract_address(self) -> ContractAddress:
        data = await self.provider.request("contract_address", None)
        return ContractAddress(**data)

    async def get_state(self, address: str) -> AccountState:
        data = await self.provider.request("account_info", [address])
        if data is None:
            raise AccountDoesNotExist(address=address)
        if "accountType" in data and isinstance(data["accountType"], dict) and \
                list(data["accountType"].keys())[0] == 'No2FA':
            data["accountType"] = 'No2FA'
        return AccountState(**data)

    async def get_account_nonce(self, address: str) -> int:
        state = await self.get_state(address)
        return state.get_nonce()

    async def get_tx_receipt(self, address: str) -> TransactionDetails:
        return await self.provider.request("tx_info", [address])

    async def get_transaction_fee(self, tx_type: FeeTxType, address: str,
                                  token_like: TokenLike) -> Fee:

        data = await self.provider.request('get_tx_fee', [tx_type.value, address, token_like])
        return Fee(**data)
