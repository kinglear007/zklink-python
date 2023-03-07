import time
from decimal import Decimal
from fractions import Fraction
from typing import List, Optional, Tuple, Union

from zklink_sdk.ethereum_provider import EthereumProvider
from zklink_sdk.ethereum_signer import EthereumSignerInterface
from zklink_sdk.types import (ChangePubKey, ChangePubKeyCREATE2, ChangePubKeyEcdsa,
                              ChangePubKeyTypes, EncodedTx, ForcedExit, Token, TokenLike,
                              Tokens, TransactionWithSignature, Transfer, TxEthSignature,
                              Withdraw, Order, RatioType,
                              token_ratio_to_wei_ratio, get_toggle_message, get_toggle_message_with_pub, Toggle2FA)
from zklink_sdk.zklink_provider import FeeTxType, ZkLinkProviderInterface
from zklink_sdk.zklink_signer import ZkLinkSigner
from zklink_sdk.zklink_provider.transaction import Transaction

DEFAULT_VALID_FROM = 0
DEFAULT_VALID_UNTIL = 2 ** 32 - 1


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
            state = await self.zk_provider.get_state(self.address())
            if isinstance(state.id, int):
                self.account_id = state.id
        return self.account_id

    async def send_signed_transaction(self, tx: EncodedTx,
                                      eth_signature: Union[Optional[TxEthSignature], List[Optional[TxEthSignature]]],
                                      fast_processing: bool = False) -> Transaction:
        return await self.zk_provider.submit_tx(tx, eth_signature, fast_processing)

    async def send_txs_batch(self, transactions: List[TransactionWithSignature],
                             signatures: Optional[
                                 Union[List[TxEthSignature], TxEthSignature]
                             ] = None) -> List[Transaction]:
        return await self.zk_provider.submit_txs_batch(transactions, signatures)

    async def set_signing_key(self, fee_token: TokenLike, *,
                              eth_auth_data: Union[ChangePubKeyCREATE2, ChangePubKeyEcdsa, None] = None,
                              fee: Optional[Decimal] = None, nonce: Optional[int] = None,
                              valid_from=DEFAULT_VALID_FROM, valid_until=DEFAULT_VALID_UNTIL):
        if nonce is None:
            nonce = await self.zk_provider.get_account_nonce(self.address())
        fee_token_obj = await self.resolve_token(fee_token)
        if isinstance(eth_auth_data, ChangePubKeyEcdsa):
            eth_auth_type = ChangePubKeyTypes.ecdsa
        elif isinstance(eth_auth_data, ChangePubKeyCREATE2):
            eth_auth_type = ChangePubKeyTypes.create2
        else:
            eth_auth_type = ChangePubKeyTypes.onchain

        if fee is None:
            if eth_auth_type == ChangePubKeyTypes.ecdsa:
                fee_obj = await self.zk_provider.get_transaction_fee(FeeTxType.change_pub_key_ecdsa,
                                                                     self.address(),
                                                                     fee_token_obj.id)
            elif eth_auth_type == ChangePubKeyTypes.onchain:
                fee_obj = await self.zk_provider.get_transaction_fee(FeeTxType.change_pub_key_onchain,
                                                                     self.address(),
                                                                     fee_token_obj.id)
            else:
                assert eth_auth_type == ChangePubKeyTypes.create2, "invalid eth_auth_type"
                fee_obj = await self.zk_provider.get_transaction_fee(FeeTxType.change_pub_key_create2,
                                                                     self.address(),
                                                                     fee_token_obj.id)
            fee_int = fee_obj.total_fee
        else:
            fee_int = fee_token_obj.from_decimal(fee)

        change_pub_key, eth_signature = await self.build_change_pub_key(fee_token_obj,
                                                                        eth_auth_data, fee_int,
                                                                        nonce,
                                                                        valid_from,
                                                                        valid_until)

        return await self.send_signed_transaction(change_pub_key, eth_signature)

    # This function takes as a parameter the integer fee of 
    # lowest token denominations (wei, satoshi, etc.)
    async def build_change_pub_key(
            self,
            fee_token: Token,
            eth_auth_data: Union[ChangePubKeyCREATE2, ChangePubKeyEcdsa, None],
            fee: int,
            nonce: Optional[int] = None,
            valid_from=DEFAULT_VALID_FROM,
            valid_until=DEFAULT_VALID_UNTIL):
        if nonce is None:
            nonce = await self.zk_provider.get_account_nonce(self.address())
        account_id = await self.get_account_id()

        new_pubkey_hash = self.zk_signer.pubkey_hash_str()
        change_pub_key = ChangePubKey(
            account=self.address(),
            account_id=account_id,
            new_pk_hash=new_pubkey_hash,
            token=fee_token,
            fee=fee,
            nonce=nonce,
            valid_until=valid_until,
            valid_from=valid_from,
            eth_auth_data=eth_auth_data
        )

        eth_signature = self.eth_signer.sign(change_pub_key.get_eth_tx_bytes())
        eth_auth_data = change_pub_key.get_auth_data(eth_signature.signature)

        change_pub_key.eth_auth_data = eth_auth_data
        zk_signature = self.zk_signer.sign_tx(change_pub_key)
        change_pub_key.signature = zk_signature

        return change_pub_key, eth_signature

    async def forced_exit(self, target: str, token: TokenLike, fee: Optional[Decimal] = None,
                          valid_from=DEFAULT_VALID_FROM, valid_until=DEFAULT_VALID_UNTIL) -> Transaction:
        nonce = await self.zk_provider.get_account_nonce(self.address())
        token_obj = await self.resolve_token(token)
        if fee is None:
            fee_obj = await self.zk_provider.get_transaction_fee(FeeTxType.withdraw, target, token_obj.id)
            fee_int = fee_obj.total_fee
        else:
            fee_int = token_obj.from_decimal(fee)

        transfer, eth_signature = await self.build_forced_exit(target, token_obj, fee_int, nonce,
                                                               valid_from, valid_until)

        return await self.send_signed_transaction(transfer, eth_signature)

    # This function takes as a parameter the integer fee of 
    # lowest token denominations (wei, satoshi, etc.)
    async def build_forced_exit(
            self,
            target: str,
            token: Token,
            fee: int,
            nonce: Optional[int] = None,
            valid_from=DEFAULT_VALID_FROM,
            valid_until=DEFAULT_VALID_UNTIL) -> Tuple[ForcedExit, TxEthSignature]:
        if nonce is None:
            nonce = await self.zk_provider.get_account_nonce(self.address())
        account_id = await self.get_account_id()

        forced_exit = ForcedExit(initiator_account_id=account_id,
                                 target=target,
                                 fee=fee,
                                 nonce=nonce,
                                 valid_from=valid_from,
                                 valid_until=valid_until,
                                 token=token)
        eth_signature = self.eth_signer.sign_tx(forced_exit)
        zk_signature = self.zk_signer.sign_tx(forced_exit)
        forced_exit.signature = zk_signature

        return forced_exit, eth_signature

    def address(self):
        return self.eth_signer.address()

    async def build_transfer(
            self,
            to: str,
            amount: int,
            token: Token,
            fee: int,
            nonce: Optional[int] = None,
            valid_from: int = DEFAULT_VALID_FROM,
            valid_until: int = DEFAULT_VALID_UNTIL,
    ) -> Tuple[Transfer, TxEthSignature]:
        """
        This function takes as a parameter the integer amount/fee of lowest token denominations (wei, satoshi, etc.)
        """
        if nonce is None:
            nonce = await self.zk_provider.get_account_nonce(self.address())
        account_id = await self.get_account_id()

        transfer = Transfer(account_id=account_id, from_address=self.address(),
                            to_address=to.lower(),
                            amount=amount, fee=fee,
                            nonce=nonce,
                            valid_from=valid_from,
                            valid_until=valid_until,
                            token=token)
        eth_signature = self.eth_signer.sign_tx(transfer)
        zk_signature = self.zk_signer.sign_tx(transfer)
        transfer.signature = zk_signature
        return transfer, eth_signature

    async def transfer(self, to: str, amount: Decimal, token: TokenLike,
                       fee: Optional[Decimal] = None,
                       valid_from=DEFAULT_VALID_FROM, valid_until=DEFAULT_VALID_UNTIL) -> Transaction:
        nonce = await self.zk_provider.get_account_nonce(self.address())
        token_obj = await self.resolve_token(token)

        if fee is None:
            fee_obj = await self.zk_provider.get_transaction_fee(FeeTxType.transfer, to, token_obj.id)
            fee_int = fee_obj.total_fee
        else:
            fee_int = token_obj.from_decimal(fee)

        amount_int = token_obj.from_decimal(amount)

        transfer, eth_signature = await self.build_transfer(to, amount_int, token_obj, fee_int, nonce, valid_from,
                                                            valid_until)
        return await self.send_signed_transaction(transfer, eth_signature)

    async def get_order(self, token_sell: TokenLike, token_buy: TokenLike,
                        ratio: Fraction, ratio_type: RatioType, amount: Decimal,
                        recipient: Optional[str] = None,
                        nonce: Optional[int] = None,
                        valid_from=DEFAULT_VALID_FROM,
                        valid_until=DEFAULT_VALID_UNTIL) -> Order:
        if nonce is None:
            nonce = await self.zk_provider.get_account_nonce(self.address())
        token_sell_obj = await self.resolve_token(token_sell)
        token_buy_obj = await self.resolve_token(token_buy)
        recipient = recipient or self.address()

        if ratio_type == RatioType.token:
            ratio = token_ratio_to_wei_ratio(ratio, token_sell_obj, token_buy_obj)

        account_id = await self.get_account_id()

        order = Order(account_id=account_id, recipient=recipient,
                      token_sell=token_sell_obj,
                      token_buy=token_buy_obj,
                      ratio=ratio,
                      amount=token_sell_obj.from_decimal(amount),
                      nonce=nonce,
                      valid_from=valid_from,
                      valid_until=valid_until)

        order.eth_signature = self.eth_signer.sign_tx(order)
        order.signature = self.zk_signer.sign_tx(order)

        return order

    async def get_limit_order(self, token_sell: TokenLike, token_buy: TokenLike,
                              ratio: Fraction, ratio_type: RatioType,
                              recipient: Optional[str] = None,
                              valid_from=DEFAULT_VALID_FROM,
                              valid_until=DEFAULT_VALID_UNTIL):
        return await self.get_order(token_sell, token_buy, ratio, ratio_type, Decimal(0), recipient, valid_from,
                                    valid_until)

    # This function takes as a parameter the integer amount/fee of
    # lowest token denominations (wei, satoshi, etc.)
    async def build_withdraw(self, eth_address: str, amount: int, token: Token,
                             fee: int,
                             nonce: Optional[int] = None,
                             valid_from=DEFAULT_VALID_FROM,
                             valid_until=DEFAULT_VALID_UNTIL):
        if nonce is None:
            nonce = await self.zk_provider.get_account_nonce(self.address())
        account_id = await self.get_account_id()

        withdraw = Withdraw(account_id=account_id, from_address=self.address(),
                            to_address=eth_address,
                            amount=amount, fee=fee,
                            nonce=nonce,
                            valid_from=valid_from,
                            valid_until=valid_until,
                            token=token)
        eth_signature = self.eth_signer.sign_tx(withdraw)
        zk_signature = self.zk_signer.sign_tx(withdraw)
        withdraw.signature = zk_signature
        return withdraw, eth_signature

    async def withdraw(self, eth_address: str, amount: Decimal, token: TokenLike,
                       fee: Optional[Decimal] = None, fast: bool = False,
                       valid_from=DEFAULT_VALID_FROM, valid_until=DEFAULT_VALID_UNTIL) -> Transaction:
        nonce = await self.zk_provider.get_account_nonce(self.address())
        token_obj = await self.resolve_token(token)
        if fee is None:
            tx_type = FeeTxType.fast_withdraw if fast else FeeTxType.withdraw
            fee_obj = await self.zk_provider.get_transaction_fee(tx_type, eth_address, token_obj.id)
            fee_int = fee_obj.total_fee
        else:
            fee_int = token_obj.from_decimal(fee)
        amount_int = token_obj.from_decimal(amount)

        withdraw, eth_signature = await self.build_withdraw(eth_address, amount_int, token_obj, fee_int, nonce,
                                                            valid_from, valid_until)
        return await self.send_signed_transaction(withdraw, eth_signature, fast)

    async def get_balance(self, token: TokenLike, type: str):
        account_state = await self.get_account_state()
        token_obj = await self.resolve_token(token)

        if type == "committed":
            token_balance = account_state.committed.balances.get(token_obj.symbol)
        else:
            token_balance = account_state.verified.balances.get(token_obj.symbol)
        if token_balance is None:
            token_balance = 0
        return token_balance

    async def get_account_state(self):
        return await self.zk_provider.get_state(self.address())

    async def is_signing_key_set(self) -> bool:
        account_state = await self.get_account_state()
        signer_pub_key_hash = self.zk_signer.pubkey_hash_str()
        return account_state.id is not None and \
               account_state.committed.pub_key_hash == signer_pub_key_hash

    async def resolve_token(self, token: TokenLike) -> Token:
        resolved_token = self.tokens.find(token)
        if resolved_token is not None:
            return resolved_token
        self.tokens = await self.zk_provider.get_tokens()
        resolved_token = self.tokens.find(token)
        if resolved_token is None:
            raise TokenNotFoundError
        return resolved_token

    async def enable_2fa(self) -> bool:
        mil_seconds = int(time.time() * 1000)
        msg = get_toggle_message(True, mil_seconds)
        eth_sig = self.eth_signer.sign(msg.encode())
        account_id = await self.get_account_id()
        toggle = Toggle2FA(True,
                           account_id,
                           mil_seconds,
                           eth_sig,
                           None
                           )
        return await self.zk_provider.toggle_2fa(toggle)

    async def disable_2fa(self, pub_key_hash: Optional[str]) -> bool:
        mil_seconds = int(time.time() * 1000)
        if pub_key_hash is None:
            msg = get_toggle_message(False, mil_seconds)
        else:
            msg = get_toggle_message_with_pub(False, mil_seconds, pub_key_hash)
        eth_sig = self.eth_signer.sign(msg.encode())
        account_id = await self.get_account_id()
        toggle = Toggle2FA(False,
                           account_id,
                           mil_seconds,
                           eth_sig,
                           pub_key_hash)
        return await self.zk_provider.toggle_2fa(toggle)

    async def disable_2fa_with_pub_key(self):
        pub_key_hash = self.zk_signer.pubkey_hash_str()
        return await self.disable_2fa(pub_key_hash)
