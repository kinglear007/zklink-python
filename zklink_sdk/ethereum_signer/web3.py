from eth_account.messages import encode_defunct, encode_structured_data
from eth_account.signers.base import BaseAccount
from zklink_sdk.ethereum_signer.interface import EthereumSignerInterface
from zklink_sdk.types import EncodedTx, SignatureType, TxEthSignature
from typing import Union
from collections.abc import (
    Mapping,
)

__all__ = ['EthereumSignerWeb3']


class EthereumSignerWeb3(EthereumSignerInterface):
    def __init__(self, account: BaseAccount):
        self.account = account

    def sign_tx(self, tx: EncodedTx) -> TxEthSignature:
        message = tx.human_readable_message()
        return self.sign(message.encode())

    def sign(self, message: Union[bytes, Mapping]) -> TxEthSignature:
        if isinstance(message, Mapping):
            signature = self.account.sign_message(encode_structured_data(message))
        else:
            signature = self.account.sign_message(encode_defunct(message))
        return TxEthSignature(signature=signature.signature, sig_type=SignatureType.ethereum_signature)

    def address(self) -> str:
        return self.account.address
