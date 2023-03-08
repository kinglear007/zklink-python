import abc
import hashlib
from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
from enum import Enum, IntEnum
from typing import List, Optional, Union, Tuple

from pydantic import BaseModel
from zklink_sdk.lib import ZkLinkLibrary
from zklink_sdk.serializers import (int_to_bytes, packed_amount_checked, packed_fee_checked,
                                    serialize_account_id,
                                    serialize_address, serialize_content_hash,
                                    serialize_nonce, serialize_timestamp,
                                    serialize_token_id, serialize_ratio_part,
                                    serialize_sub_account_id, serialize_chain_id,
                                    serialize_slot_id, serialize_order_nonce)
from zklink_sdk.types.signatures import TxEthSignature, TxSignature, OrderSignature
from zklink_sdk.types.auth_types import ChangePubKeyCREATE2, ChangePubKeyEcdsa

DEFAULT_TOKEN_ADDRESS = "0x0000000000000000000000000000000000000000"


TRANSACTION_VERSION = 0x01


class EncodedTxType(IntEnum):
    CHANGE_PUB_KEY = 6
    TRANSFER = 4
    WITHDRAW = 3
    FORCED_EXIT = 7
    ORDER_MATCHING = 8


class RatioType(Enum):
    # ratio that represents the lowest denominations of tokens (wei for ETH, satoshi for BTC etc.)
    wei = 'Wei',
    # ratio that represents tokens themselves
    token = 'Token'


class Token(BaseModel):
    address: str
    id: int
    symbol: str
    decimals: int
    chain_id: int

    @classmethod
    def eth(cls):
        return cls(id=0, chain_id=0,
                   address=DEFAULT_TOKEN_ADDRESS,
                   symbol="ETH",
                   decimals=18)

    def is_eth(self) -> bool:
        return self.symbol == "ETH" and self.address == DEFAULT_TOKEN_ADDRESS

    def decimal_amount(self, amount: int) -> Decimal:
        return Decimal(amount).scaleb(-self.decimals)

    def from_decimal(self, amount: Decimal) -> int:
        return int(amount.scaleb(self.decimals))

    def decimal_str_amount(self, amount: int) -> str:
        d = self.decimal_amount(amount)

        # Creates a string with `self.decimals` numbers after decimal point.
        # Prevents scientific notation (string values like '1E-8').
        # Prevents integral numbers having no decimal point in the string representation.
        d_str = f"{d:.{self.decimals}f}"

        d_str = d_str.rstrip("0")
        if d_str[-1] == ".":
            return d_str + "0"

        if '.' not in d_str:
            return d_str + '.0'

        return d_str


def token_ratio_to_wei_ratio(token_ratio: Fraction, token_sell: Token, token_buy: Token) -> Fraction:
    num = token_sell.from_decimal(Decimal(token_ratio.numerator))
    den = token_buy.from_decimal(Decimal(token_ratio.denominator))
    return Fraction(num, den, _normalize=False)


class Tokens(BaseModel):
    tokens: List[Token]

    def find_by_address(self, address: str) -> Optional[Token]:
        found_token = [token for token in self.tokens if token.address == address]
        if found_token:
            return found_token[0]
        else:
            return None

    def find_by_id(self, token_id: int, chain_id: int) -> Optional[Token]:
        found_token = [token for token in self.tokens if token.id == token_id and token.chain_id == chain_id]
        if found_token:
            return found_token[0]
        else:
            return None

    def find_by_symbol(self, symbol: str, chain_id: int) -> Optional[Token]:
        found_token = [token for token in self.tokens if token.symbol == symbol and token.chain_id == chain_id]
        if found_token:
            return found_token[0]
        else:
            return None


class Order(BaseModel):
    account_id: int
    sub_account_id: int
    slot: int
    nonce: int
    base_token: Token
    quote_token: Token
    amount: int
    price: int
    is_sell: int
    maker_fee_ratio: int
    taker_fee_ratio: int
    signature: Optional[OrderSignature]

    def encoded_message(self) -> bytes:
        return b"".join([
            int_to_bytes(0xff, 1),
            serialize_account_id(self.account_id),
            serialize_sub_account_id(self.sub_account_id),
            serialize_slot_id(self.slot),
            serialize_order_nonce(self.nonce),
            serialize_token_id(self.base_token.id),
            serialize_token_id(self.quote_token.id),
            int_to_bytes(self.price, 15),
            int_to_bytes(self.is_sell, 1),
            int_to_bytes(self.maker_fee_ratio, 1),
            int_to_bytes(self.taker_fee_ratio, 1),
            packed_amount_checked(self.amount),
        ])

    def dict(self):
        return {
            "accountId": self.account_id,
            "subAccountId": self.sub_account_id,
            "slotId": self.slot,
            "nonce": self.nonce,
            "baseTokenId": self.base_token.id,
            "quoteTokenId": self.quote_token.id,
            "amount": str(self.amount),
            "price": str(self.price),
            "isSell": self.is_sell,
            "feeRatio1": self.maker_fee_ratio,
            "feeRatio2": self.taker_fee_ratio,
            "signature": self.signature.dict()
        }


class EncodedTx(abc.ABC):
    @abc.abstractmethod
    def encoded_message(self) -> bytes:
        pass

    @abc.abstractmethod
    def human_readable_message(self) -> str:
        pass

    @abc.abstractmethod
    def tx_type(self) -> int:
        pass

    @abc.abstractmethod
    def dict(self):
        pass

    @abc.abstractmethod
    def batch_message_part(self) -> str:
        pass

    @abc.abstractmethod
    def tx_hash(self) -> str:
        pass


@dataclass
class ChangePubKey(EncodedTx):
    chain_id: int
    account_id: int
    sub_account_id: int
    new_pk_hash: str
    fee_token: Token
    fee: int
    nonce: int
    timestamp: int
    eth_auth_data: Union[ChangePubKeyCREATE2, ChangePubKeyEcdsa, None] = None
    eth_signature: Optional[TxEthSignature] = None

    signature: Optional[TxSignature] = None

    def encoded_message(self) -> bytes:
        return b"".join([
            int_to_bytes(self.tx_type(), 1),
            serialize_chain_id(self.chain_id),
            serialize_account_id(self.account_id),
            serialize_sub_account_id(self.sub_account_id),
            serialize_address(self.new_pk_hash),
            serialize_token_id(self.fee_token.id),
            packed_fee_checked(self.fee),
            serialize_nonce(self.nonce),
            serialize_timestamp(self.timestamp)
        ])

    def get_eth_tx_bytes(self) -> bytes:
        data = b"".join([
            serialize_address(self.new_pk_hash),
            serialize_nonce(self.nonce),
            serialize_account_id(self.account_id),
        ])
        if self.eth_auth_data is not None:
            data += self.eth_auth_data.encode_message()
        return data

    def get_auth_data(self, signature: str):
        if self.eth_auth_data is None:
            return {"type": "Onchain"}
        elif isinstance(self.eth_auth_data, ChangePubKeyEcdsa):
            return self.eth_auth_data.dict(signature)
        elif isinstance(self.eth_auth_data, ChangePubKeyCREATE2):
            return self.eth_auth_data.dict()

    def dict(self):
        return {
            "type": "ChangePubKey",
            "chainId": self.chain_id,
            "accountId": self.account_id,
            "subAccountId": self.sub_account_id,
            "newPkHash": self.new_pk_hash,
            "feeToken": self.fee_token.id,
            "fee": str(self.fee),
            "nonce": self.nonce,
            "ethAuthData": self.eth_auth_data,
            "ethSignature": self.eth_signature.dict(),
            "signature": self.signature.dict(),
            "ts": self.timestamp
        }

    @classmethod
    def tx_type(cls):
        return EncodedTxType.CHANGE_PUB_KEY

    def tx_hash(self) -> str:
        return "sync-tx:{}".format(hashlib.sha256(self.encoded_message()).hexdigest())


@dataclass
class Transfer(EncodedTx):
    account_id: int
    from_sub_account_id: int
    to_address: str
    to_sub_account_id: int
    token: Token
    amount: int
    fee: int
    nonce: int
    timestamp: int

    signature: Optional[TxSignature] = None

    def tx_type(self) -> int:
        return EncodedTxType.TRANSFER

    def human_readable_message(self) -> str:
        msg = ""
        if self.amount != 0:
            msg += f"Transfer {self.token.decimal_str_amount(self.amount)} {self.token.symbol} to: {self.to_address.lower()}\n"
        if self.fee != 0:
            msg += f"Fee: {self.token.decimal_str_amount(self.fee)} {self.token.symbol}\n"
        return msg + f"Nonce: {self.nonce}"

    def encoded_message(self) -> bytes:
        return b"".join([
            int_to_bytes(self.tx_type(), 1),
            serialize_account_id(self.account_id),
            serialize_sub_account_id(self.from_sub_account_id),
            serialize_address(self.to_address),
            serialize_sub_account_id(self.to_sub_account_id),
            serialize_token_id(self.token.id),
            packed_amount_checked(self.amount),
            packed_fee_checked(self.fee),
            serialize_nonce(self.nonce),
            serialize_timestamp(self.timestamp)
        ])

    def dict(self):
        return {
            "type": "Transfer",
            "accountId": self.account_id,
            "fromSubAccountId": self.from_sub_account_id,
            "to": self.to_address,
            "toSubAccountId": self.to_sub_account_id,
            "token": self.token.id,
            "fee": str(self.fee),
            "nonce": self.nonce,
            "signature": self.signature.dict(),
            "amount": str(self.amount),
            "ts": self.timestamp
        }

    def tx_hash(self) -> str:
        return "sync-tx:{}".format(hashlib.sha256(self.encoded_message()).hexdigest())


@dataclass
class Withdraw(EncodedTx):
    to_chain_id: int
    account_id: int
    sub_account_id: int
    to_address: str
    l2_source_token: Token
    l1_target_token: Token
    amount: int
    fee: int
    nonce: int
    fast_withdraw: int
    withdraw_fee_ratio: int
    timestamp: int

    signature: Optional[TxSignature] = None

    def tx_type(self) -> int:
        return EncodedTxType.WITHDRAW

    def human_readable_message(self) -> str:
        msg = ""
        if self.amount != 0:
            msg += f"Withdraw {self.l2_source_token.decimal_str_amount(self.amount)} {self.l2_source_token.symbol} to: {self.to_address.lower()}\n"
        if self.fee != 0:
            msg += f"Fee: {self.l2_source_token.decimal_str_amount(self.fee)} {self.l2_source_token.symbol}\n"
        return msg + f"Nonce: {self.nonce}"

    def encoded_message(self) -> bytes:
        return b"".join([
            int_to_bytes(self.tx_type(), 1),
            serialize_chain_id(self.to_chain_id),
            serialize_account_id(self.account_id),
            serialize_sub_account_id(self.sub_account_id),
            serialize_address(self.to_address),
            serialize_token_id(self.l2_source_token.id),
            serialize_token_id(self.l1_target_token.id),
            int_to_bytes(self.amount, length=16),
            packed_fee_checked(self.fee),
            serialize_nonce(self.nonce),
            int_to_bytes(self.fast_withdraw, 1),
            int_to_bytes(self.withdraw_fee_ratio, 2),
            serialize_timestamp(self.timestamp)
        ])

    def dict(self):
        return {
            "type": "Withdraw",
            "toChainId": self.to_chain_id,
            "accountId": self.account_id,
            "subAccountId": self.sub_account_id,
            "to": self.to_address,
            "l2SourceToken": self.l2_source_token.id,
            "l1TargetToken": self.l1_target_token.id,
            "fee": str(self.fee),
            "nonce": self.nonce,
            "signature": self.signature.dict(),
            "amount": str(self.amount),
            "fastWithdraw": self.fast_withdraw,
            "withdrawFeeRatio": self.withdraw_fee_ratio,
            "ts": self.timestamp
        }

    def tx_hash(self) -> str:
        return "sync-tx:{}".format(hashlib.sha256(self.encoded_message()).hexdigest())


@dataclass
class ForcedExit(EncodedTx):
    to_chain_id: int
    initiator_account_id: int
    initiator_sub_account_id: int
    target: str
    target_sub_account_id: int
    l2_source_token: Token
    l1_target_token: Token
    fee_token: Token
    fee: int
    nonce: int
    timestamp: int

    signature: Optional[TxSignature] = None

    def tx_type(self) -> int:
        return EncodedTxType.FORCED_EXIT

    def encoded_message(self) -> bytes:
        return b"".join([
            int_to_bytes(self.tx_type(), 1),
            serialize_chain_id(self.to_chain_id),
            serialize_account_id(self.initiator_account_id),
            serialize_sub_account_id(self.initiator_sub_account_id),
            serialize_address(self.target),
            serialize_sub_account_id(self.target_sub_account_id),
            serialize_token_id(self.l2_source_token.id),
            serialize_token_id(self.l1_target_token.id),
            serialize_token_id(self.fee_token.id),
            packed_fee_checked(self.fee),
            serialize_nonce(self.nonce),
            serialize_timestamp(self.timestamp)
        ])

    def human_readable_message(self) -> str:
        msg = ""
        msg += f"ForcedExit {self.l2_source_token.symbol} to: {self.target.lower()}\n"
        if self.fee != 0:
            msg += f"Fee: {self.fee_token.decimal_str_amount(self.fee)} {self.fee_token.symbol}\n"
        return msg + f"Nonce: {self.nonce}"

    def dict(self):
        return {
            "type": "ForcedExit",
            "toChainId": self.to_chain_id,
            "initiatorAccountId": self.initiator_account_id,
            "initiatorSubAccountId": self.initiator_sub_account_id,
            "target": self.target,
            "targetSubAccountId": self.target_sub_account_id,
            "l2SourceToken": self.l2_source_token.id,
            "l1TargetToken": self.l1_target_token.id,
            "feeToken": self.fee_token.id,
            "fee": str(self.fee),
            "nonce": self.nonce,
            "signature": self.signature.dict(),
            "ts": self.timestamp
        }

    def tx_hash(self) -> str:
        return "sync-tx:{}".format(hashlib.sha256(self.encoded_message()).hexdigest())


@dataclass
class OrderMatching(EncodedTx):
    account_id: int
    sub_account_id: int
    taker: Order
    maker: Order
    fee_token: Token
    fee: int
    expect_base_amount: int
    expect_quote_amount: int

    signature: Optional[TxSignature] = None

    def tx_type(self) -> int:
        return EncodedTxType.ORDER_MATCHING

    def encoded_message(self) -> bytes:
        return b"".join([
            int_to_bytes(self.tx_type(), 1),
            serialize_account_id(self.account_id),
            serialize_sub_account_id(self.sub_account_id),
            ZkLinkLibrary().hash_orders(self.maker.encoded_message() + self.taker.encoded_message()),
            serialize_token_id(self.fee_token.id),
            packed_fee_checked(self.fee),
            int_to_bytes(self.expect_base_amount, 16),
            int_to_bytes(self.expect_quote_amount, 16)
        ])

    def dict(self):
        return {
            "type": "OrderMatching",
            "accountId": self.account_id,
            "subAccountId": self.sub_account_id,
            "taker": self.taker.dict(),
            "maker": self.maker.dict(),
            "feeToken": self.fee_token.id,
            "fee": str(self.fee),
            "expectBaseAmount": str(self.expect_base_amount),
            "expectQuoteAmount": str(self.expect_quote_amount),
            "signature": self.signature.dict()
        }

    def tx_hash(self) -> str:
        return "sync-tx:{}".format(hashlib.sha256(self.encoded_message()).hexdigest())


class EncodedTxValidator:
    def __init__(self, library: ZkLinkLibrary):
        self.library = library

    def is_valid_signature(self, tx):
        zk_sync_signature: TxSignature = tx.signature
        if zk_sync_signature is None:
            return False
        bytes_signature = bytes.fromhex(zk_sync_signature.signature)
        pubkey = bytes.fromhex(zk_sync_signature.public_key)
        return self.library.is_valid_signature(tx.encoded_message(), pubkey, bytes_signature)


@dataclass
class TransactionWithSignature:
    tx: EncodedTx
    signature: TxEthSignature

    def dict(self):
        return {
            'tx': self.tx.dict(),
            'signature': self.signature.dict(),
        }


@dataclass()
class TransactionWithOptionalSignature:
    tx: EncodedTx
    signature: Optional[TxEthSignature] = None

    def dict(self):
        return {
            'signature': self.signature.dict() if self.signature is not None else None,
            'tx': self.tx.dict()
        }
