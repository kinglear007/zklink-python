import time
from decimal import Decimal
from fractions import Fraction
from typing import List, Optional, Tuple, Union

from zklink_sdk.ethereum_provider import EthereumProvider
from zklink_sdk.ethereum_signer import EthereumSignerInterface
from zklink_sdk.types import (ChangePubKey, ChangePubKeyCREATE2, ChangePubKeyEcdsa,
                              ChangePubKeyTypes, EncodedTx, ForcedExit, Token,
                              Tokens, TransactionWithSignature, Transfer, TxEthSignature,
                              Withdraw, Order, RatioType, SubmitSignature,
                              token_ratio_to_wei_ratio, )
from zklink_sdk.zklink_provider import FeeTxType, ZkLinkProviderInterface
from zklink_sdk.zklink_signer import ZkLinkSigner
from zklink_sdk.zklink_provider.transaction import Transaction


class WalletError(Exception):
    pass


class TokenNotFoundError(WalletError):
    pass


class AmountsMissing(WalletError):
    pass


class Wallet:
    def __init__(self, ethereum_provider: EthereumProvider, zk_signer: ZkLinkSigner,
                 eth_signer: EthereumSignerInterface, provider: ZkLinkProviderInterface):
        self.ethereum_provider = ethereum_provider
        self.zk_signer = zk_signer
        self.eth_signer = eth_signer
        self.zk_provider = provider
        self.account_id = None
        self.tokens = Tokens(tokens=[])

    async def get_account_id(self):
        if self.account_id is None:
            state = await self.zk_provider.get_account(self.address())
            if isinstance(state.id, int):
                self.account_id = state.id
        return self.account_id

    async def send_signed_transaction(self, tx: EncodedTx,
                                      eth_signature: Optional[TxEthSignature],
                                      submitter_signature: Optional[SubmitSignature] = None) -> Transaction:
        return await self.zk_provider.send_transaction(tx, eth_signature, submitter_signature)

    async def change_pubkey(self, chain_id: int, fee_token: Token, sub_account_id: int,
                            eth_auth_data: Union[ChangePubKeyCREATE2, ChangePubKeyEcdsa, None] = None,
                            fee: Optional[Decimal] = None, nonce: Optional[int] = None):
        if nonce is None:
            nonce = await self.zk_provider.get_account_nonce(self.address())

        if fee is None:
            change_pub_key, _ = await self.build_change_pub_key(fee_token,
                                                                eth_auth_data, 0, chain_id, sub_account_id, nonce)
            fee_int = await self.zk_provider.estimate_transaction_fee(change_pub_key)
        else:
            fee_int = fee_token.from_decimal(fee)

        change_pub_key, eth_signature = await self.build_change_pub_key(fee_token,
                                                                        eth_auth_data, fee_int, chain_id,
                                                                        sub_account_id, nonce)

        return await self.send_signed_transaction(change_pub_key, eth_signature)

    # This function takes as a parameter the integer fee of 
    # lowest token denominations (wei, satoshi, etc.)
    async def build_change_pub_key(
            self,
            fee_token: Token,
            eth_auth_data: Union[ChangePubKeyCREATE2, ChangePubKeyEcdsa, None],
            fee: int,
            chain_id: int,
            sub_account_id: int,
            nonce: Optional[int] = None,
            timestamp: int = int(time.time())):
        if nonce is None:
            nonce = await self.zk_provider.get_account_nonce(self.address())
        account_id = await self.get_account_id()

        new_pubkey_hash = self.zk_signer.pubkey_hash_str()
        change_pub_key = ChangePubKey(
            chain_id=chain_id,
            account_id=account_id,
            sub_account_id=sub_account_id,
            new_pk_hash=new_pubkey_hash,
            fee_token=fee_token,
            fee=fee,
            nonce=nonce,
            timestamp=timestamp,
            eth_auth_data=eth_auth_data,
        )
        contract = await self.zk_provider.get_contract_address(chain_id)

        eth_signature = self.eth_signer.sign(
            change_pub_key.get_eth_tx_bytes(contract.main_contract, contract.layer1_chain_id))

        eth_auth_data = change_pub_key.get_auth_data(eth_signature.signature)

        change_pub_key.eth_auth_data = eth_auth_data
        zk_signature = self.zk_signer.sign_tx(change_pub_key)
        change_pub_key.signature = zk_signature

        return change_pub_key, eth_signature

    async def forced_exit(self, to_chain_id: int, initiator_sub_account_id: int, target: str,
                          target_sub_account_id: int, l2_source_token: Token, l1_target_token: Token,
                          fee_token: Token, fee: Optional[Decimal] = None) -> Transaction:
        nonce = await self.zk_provider.get_account_nonce(self.address())
        if fee is None:
            forced_exit, _ = await self.build_forced_exit(to_chain_id, initiator_sub_account_id, target,
                                                          target_sub_account_id,
                                                          l2_source_token, l1_target_token, fee_token,
                                                          0, nonce)

            fee_int = await self.zk_provider.estimate_transaction_fee(forced_exit)
        else:
            fee_int = fee_token.from_decimal(fee)

        forced_exit, eth_signature = await self.build_forced_exit(to_chain_id, initiator_sub_account_id, target,
                                                                  target_sub_account_id,
                                                                  l2_source_token, l1_target_token, fee_token,
                                                                  fee_int, nonce)

        return await self.send_signed_transaction(forced_exit, eth_signature)

    # This function takes as a parameter the integer fee of 
    # lowest token denominations (wei, satoshi, etc.)
    async def build_forced_exit(
            self,
            to_chain_id: int,
            initiator_sub_account_id: int,
            target: str,
            target_sub_account_id: int,
            l2_source_token: Token,
            l1_target_token: Token,
            fee_token: Token,
            fee: int,
            nonce: Optional[int] = None,
            timestamp: int = int(time.time())) -> Tuple[ForcedExit, TxEthSignature]:
        if nonce is None:
            nonce = await self.zk_provider.get_account_nonce(self.address())
        account_id = await self.get_account_id()

        forced_exit = ForcedExit(
            to_chain_id=to_chain_id,
            initiator_account_id=account_id,
            initiator_sub_account_id=initiator_sub_account_id,
            target=target,
            target_sub_account_id=target_sub_account_id,
            l2_source_token=l2_source_token,
            l1_target_token=l1_target_token,
            fee_token=fee_token,
            fee=fee,
            nonce=nonce,
            timestamp=timestamp
        )
        eth_signature = self.eth_signer.sign_tx(forced_exit)
        zk_signature = self.zk_signer.sign_tx(forced_exit)
        forced_exit.signature = zk_signature

        return forced_exit, eth_signature

    def address(self):
        return self.eth_signer.address()

    async def build_transfer(
            self,
            from_sub_account_id: int,
            to: str,
            to_sub_account_id: int,
            amount: int,
            token: Token,
            fee: int,
            nonce: Optional[int] = None,
            timestamp: int = int(time.time())) -> Tuple[Transfer, TxEthSignature]:
        """
        This function takes as a parameter the integer amount/fee of lowest token denominations (wei, satoshi, etc.)
        """
        if nonce is None:
            nonce = await self.zk_provider.get_account_nonce(self.address())
        account_id = await self.get_account_id()

        transfer = Transfer(
            account_id=account_id,
            from_sub_account_id=from_sub_account_id,
            to_address=to.lower(),
            to_sub_account_id=to_sub_account_id,
            token=token,
            amount=amount,
            fee=fee,
            nonce=nonce,
            timestamp=timestamp,
        )
        eth_signature = self.eth_signer.sign_tx(transfer)
        zk_signature = self.zk_signer.sign_tx(transfer)
        transfer.signature = zk_signature
        return transfer, eth_signature

    async def transfer(self, from_sub_account_id: int, to: str, to_sub_account_id: int, amount: Decimal, token: Token,
                       fee: Optional[Decimal] = None) -> Transaction:
        nonce = await self.zk_provider.get_account_nonce(self.address())

        amount_int = token.from_decimal(amount)

        if fee is None:
            transfer, _ = await self.build_transfer(from_sub_account_id, to, to_sub_account_id, amount_int, token, 0,
                                                    nonce)
            fee_int = await self.zk_provider.estimate_transaction_fee(transfer)
        else:
            fee_int = token.from_decimal(fee)

        transfer, eth_signature = await self.build_transfer(from_sub_account_id, to, to_sub_account_id, amount_int,
                                                            token, fee_int,
                                                            nonce)
        return await self.send_signed_transaction(transfer, eth_signature)

    # This function takes as a parameter the integer amount/fee of
    # lowest token denominations (wei, satoshi, etc.)
    async def build_withdraw(self, to_chain_id: int, sub_account_id: int, eth_address: str, amount: int,
                             l2_source_token: Token,
                             l1_target_token: Token,
                             fee: int,
                             fast_withdraw: int,
                             withdraw_fee_ratio: int,
                             nonce: Optional[int] = None,
                             timestamp: int = int(time.time())):
        if nonce is None:
            nonce = await self.zk_provider.get_account_nonce(self.address())
        account_id = await self.get_account_id()

        withdraw = Withdraw(
            to_chain_id=to_chain_id,
            account_id=account_id,
            sub_account_id=sub_account_id,
            to_address=eth_address,
            l2_source_token=l2_source_token,
            l1_target_token=l1_target_token,
            amount=amount,
            fee=fee,
            fast_withdraw=fast_withdraw,
            withdraw_fee_ratio=withdraw_fee_ratio,
            nonce=nonce,
            timestamp=timestamp
        )
        eth_signature = self.eth_signer.sign_tx(withdraw)
        zk_signature = self.zk_signer.sign_tx(withdraw)
        withdraw.signature = zk_signature
        return withdraw, eth_signature

    async def withdraw(self, to_chain_id: int, sub_account_id: int, eth_address: str, amount: Decimal,
                       l2_source_token: Token,
                       l1_target_token: Token, fast_withdraw: int, withdraw_fee_ratio: int,
                       fee: Optional[Decimal] = None) -> Transaction:
        nonce = await self.zk_provider.get_account_nonce(self.address())

        amount_int = l2_source_token.from_decimal(amount)

        if fee is None:
            withdraw, _ = await self.build_withdraw(to_chain_id, sub_account_id, eth_address, amount_int,
                                                    l2_source_token, l1_target_token, 0,
                                                    fast_withdraw, withdraw_fee_ratio, nonce)
            fee_int = await self.zk_provider.estimate_transaction_fee(withdraw)
        else:
            fee_int = l2_source_token.from_decimal(fee)

        withdraw, eth_signature = await self.build_withdraw(to_chain_id, sub_account_id, eth_address, amount_int,
                                                            l2_source_token, l1_target_token, fee_int,
                                                            fast_withdraw, withdraw_fee_ratio, nonce)
        return await self.send_signed_transaction(withdraw, eth_signature)

    async def get_balance(self, sub_account_id: int, token: Token):
        account_balances = await self.zk_provider.get_account_balances(self.account_id, sub_account_id)

        token_balance = account_balances.get(token.id)
        if token_balance is None:
            token_balance = 0
        return token_balance

    async def get_account_state(self):
        return await self.zk_provider.get_account(self.address())

    async def is_signing_key_set(self) -> bool:
        account_state = await self.get_account_state()
        signer_pub_key_hash = self.zk_signer.pubkey_hash_str()
        return account_state.id is not None and account_state.pub_key_hash == signer_pub_key_hash
