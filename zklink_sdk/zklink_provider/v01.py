from dataclasses import asdict
from decimal import Decimal
from typing import List, Optional, Union
from web3 import Web3

from zklink_sdk.types import (AccountState, ContractAddress, ContractAddresses, EncodedTx, Fee, Token,
                              Tokens, TransactionDetails, TransactionWithSignature,
                              TransactionWithOptionalSignature,
                              TxEthSignature, SubmitSignature,
                              ChangePubKey, ForcedExit, Withdraw, Transfer)
from zklink_sdk.zklink_provider.error import AccountDoesNotExist, AccountBalancesDoesNotExist
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
            if len(token['chains']) != 0:
                for chain in token['chains']:
                    t = Token(address=Web3.toChecksumAddress(chain['address']),
                              chain_id=chain['chainId'],
                              decimals=chain['decimals'],
                              id=token['id'],
                              symbol=token['symbol'])
                    tokens.append(t)
            else:
                tokens.append(Token(address='',
                                    chain_id=-1,
                                    decimals=-1,
                                    id=token['id'],
                                    symbol=token['symbol']))
        return Tokens(tokens=tokens)

    async def get_support_chains(self) -> ContractAddresses:
        data = await self.provider.request("getSupportChains", None)
        addresses = [ContractAddress(
            chain_id=chain['chainId'],
            layer1_chain_id=chain['layerOneChainId'],
            main_contract=chain['mainContract'],
            gov_contract='') for chain in data]
        return ContractAddresses(addresses=addresses)

    async def get_contract_address(self, chain_id: str) -> ContractAddress:
        data = await self.provider.request("getSupportChains", None)
        for chain in data:
            if chain['chainId'] == chain_id:
                return ContractAddress(
                    chain_id=chain['chainId'],
                    layer1_chain_id=chain['layerOneChainId'],
                    main_contract=chain['mainContract'],
                    gov_contract='')

    async def get_account(self, address: str) -> AccountState:
        data = await self.provider.request("getAccount", [address])
        if data is None:
            raise AccountDoesNotExist(address=address)
        if "accountType" in data and isinstance(data["accountType"], dict) and \
                list(data["accountType"].keys())[0] == 'No2FA':
            data["accountType"] = 'No2FA'
        return AccountState(**data)

    async def get_account_nonce(self, address: str) -> int:
        state = await self.get_account(address)
        return state.get_nonce()

    async def get_account_balances(self, account_id: int, sub_account_id: int):
        data = await self.provider.request("getAccountBalances", [account_id, sub_account_id])
        if data is None:
            raise AccountBalancesDoesNotExist(account_id=account_id, sub_account_id=sub_account_id)
        return data.get(sub_account_id)

    async def get_transaction_by_hash(self, tx_hash: str, include_update: bool = True) -> TransactionDetails:
        return await self.provider.request("getTransactionByHash", [tx_hash, include_update])

    async def estimate_transaction_fee(self, tx: Union[ChangePubKey, ForcedExit, Withdraw, Transfer]) -> Fee:
        data = await self.provider.request('estimateTransactionFee', [tx])
        return Fee(**data)
