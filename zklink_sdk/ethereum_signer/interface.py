from abc import ABC, abstractmethod
from collections import Mapping
from typing import Union

from zklink_sdk.types import EncodedTx, TxEthSignature

__all__ = ['EthereumSignerInterface']


class EthereumSignerInterface(ABC):

    @abstractmethod
    def sign_tx(self, tx: EncodedTx) -> TxEthSignature:
        raise NotImplementedError

    @abstractmethod
    def sign(self, message: Union[bytes, Mapping]) -> TxEthSignature:
        raise NotImplementedError

    @abstractmethod
    def address(self) -> str:
        raise NotImplementedError
