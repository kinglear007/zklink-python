import os
from unittest import TestCase

from zklink_sdk import ZkLinkLibrary
from zklink_sdk.types.transactions import Order, Token


class TestZkLinkLibrary(TestCase):
    def setUp(self):
        self.library = ZkLinkLibrary()

    def test_public_key_hash_from_seed(self):
        seed = b"1" * 32
        key = self.library.private_key_from_seed(seed)
        assert key != seed
        pub_key = self.library.get_public_key(key)
        assert pub_key != key
        pub_key_hash = self.library.get_pubkey_hash(pub_key)
        assert pub_key != pub_key_hash

    def test_sign(self):
        seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        message = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
        key = self.library.private_key_from_seed(seed)
        signature = self.library.sign(key, message)
        pub_key = self.library.get_public_key(key)

        assert key.hex() == "0552a69519d1f3043611126c13489ff4a2a867a1c667b1d9d9031cd27fdcff5a"
        assert signature.hex() == "5462c3083d92b832d540c9068eed0a0450520f6dd2e4ab169de1a46585b394a4292896a2ebca3c0378378963a6bc1710b64c573598e73de3a33d6cec2f5d7403"
        assert pub_key.hex() == "17f3708f5e2b2c39c640def0cf0010fd9dd9219650e389114ea9da47f5874184"
        assert signature != message

    def test_sign2(self):
        key = bytes.fromhex("03619c4116463a1b9b8ff16a77ad4dd796ac4b9771913152f72be2307f6b35d8")
        message = bytes.fromhex("ff00000006010001000001000600070000000000000014d1120d7b16000000050a4a817c800a")
        signature = self.library.sign(key, message)

        assert signature.hex() == "7e00ed99c8be5e7ac9d9e2e1c5bf8ed6a5e28f1c91a0891d89a0eecd57ea411acc86a9e2073486235c0941b0666d928c109802e2a971571f3a7e845fcc087e01"

    def test_hash_orders(self):
        maker_order = Order(account_id=6, price=1500000000000000000, amount=100000000000000000000,
                            sub_account_id=1, slot=1, nonce=1,
                            base_token=Token(id=32, address='', symbol='', decimals=18),
                            quote_token=Token(id=1, address='', symbol='', decimals=18),
                            is_sell=0, taker_fee_ratio=10, maker_fee_ratio=5)
        taker_order = Order(account_id=6, price=1500000000000000000, amount=1000000000000000000,
                            sub_account_id=1, slot=3, nonce=0,
                            base_token=Token(id=32, address='', symbol='', decimals=18),
                            quote_token=Token(id=1, address='', symbol='', decimals=18),
                            is_sell=1, taker_fee_ratio=10, maker_fee_ratio=5)
        orders = maker_order.encoded_message() + taker_order.encoded_message()
        hash = self.library.hash_orders(orders)

        assert hash.hex() == "83be69c82b2c56df952594436bd024ce85ed2eaee63dadb5b3a3e1aec62388"
