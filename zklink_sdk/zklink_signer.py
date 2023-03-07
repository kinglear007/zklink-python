import hashlib

from eth_account.messages import encode_defunct
from eth_account.signers.base import BaseAccount

from zklink_sdk import ZkLinkLibrary
from zklink_sdk.types import ChainId, EncodedTx, TxSignature, Order, OrderSignature


# def derive_private_key(library: ZkLinkLibrary, message: str, account: BaseAccount,
#                        chain_id: ChainId):
#     if chain_id != ChainId.MAINNET:
#         message = f"{message}\nChain ID: {chain_id}."
#     signable_message = encode_defunct(message.encode())
#     signature = account.sign_message(signable_message)
#     private_key = library.private_key_from_seed(signature.signature)
#     return private_key


def derive_private_key(library: ZkLinkLibrary, message: str, account: BaseAccount):
    signable_message = encode_defunct(message.encode())
    signature = account.sign_message(signable_message)
    private_key = library.private_key_from_seed(signature.signature)
    return private_key


class ZkLinkSigner:
    MESSAGE = "Sign this message to create a private key to interact with zkLink's layer 2 services.\nNOTE: This application is powered by zkLink's multi-chain network.\n\nOnly sign this message for a trusted client!"

    def __init__(self, library: ZkLinkLibrary, private_key: bytes):
        self.library = library
        self.private_key = private_key
        self.public_key = self.library.get_public_key(self.private_key)

    # @classmethod
    # def from_account(cls, account: BaseAccount, library: ZkLinkLibrary, chain_id: ChainId):
    #     private_key = derive_private_key(library, cls.MESSAGE, account, chain_id)
    #     return cls(
    #         library=library,
    #         private_key=private_key,
    #     )

    @classmethod
    def from_account(cls, account: BaseAccount, library: ZkLinkLibrary):
        private_key = derive_private_key(library, cls.MESSAGE, account)
        return cls(
            library=library,
            private_key=private_key,
        )

    @classmethod
    def from_seed(cls, library: ZkLinkLibrary, seed: bytes):
        private_key = library.private_key_from_seed(seed)
        return cls(
            library=library,
            private_key=private_key,
        )

    def pubkey_hash_str(self):
        return f"sync:{self.pubkey_hash().hex()}"

    def pubkey_hash(self):
        return self.library.get_pubkey_hash(self.public_key)

    def sign_order(self, message: Order) -> OrderSignature:
        signature = self.library.sign(self.private_key, message.encoded_message())
        return OrderSignature(signature=signature, public_key=self.public_key)

    def sign_tx(self, message: EncodedTx) -> TxSignature:
        signature = self.library.sign(self.private_key, message.encoded_message())
        return TxSignature(signature=signature, public_key=self.public_key)

    def sign_tx_as_submitter(self, message: EncodedTx) -> str:
        signature = self.library.sign(self.private_key, hashlib.sha256(message.encoded_message()).digest())
        return signature.hex()
