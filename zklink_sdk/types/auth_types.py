from enum import Enum
from dataclasses import dataclass
from typing import Optional
from zklink_sdk.types.signatures import TxEthSignature


class ChangePubKeyTypes(Enum):
    onchain = "Onchain"
    ecdsa = "ECDSA"
    create2 = "CREATE2"


@dataclass
class ChangePubKeyEcdsa:
    batch_hash: bytes = b"\x00" * 32

    def encode_message(self) -> bytes:
        return self.batch_hash

    def dict(self, signature: str):
        return {"type": "ECDSA",
                "ethSignature": signature,
                "batchHash": f"0x{self.batch_hash.hex()}"}


@dataclass
class ChangePubKeyCREATE2:
    creator_address: str
    salt_arg: bytes
    code_hash: bytes

    def encode_message(self) -> bytes:
        return self.salt_arg

    def dict(self):
        return {"type": "CREATE2",
                "saltArg": f"0x{self.salt_arg.hex()}",
                "codeHash": f"0x{self.code_hash.hex()}"}


