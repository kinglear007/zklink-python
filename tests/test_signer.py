from unittest import TestCase
from fractions import Fraction

from web3 import Account

from zklink_sdk import ZkLinkLibrary, EthereumSignerWeb3
from zklink_sdk.serializers import closest_packable_amount, closest_packable_transaction_fee
from zklink_sdk.types import ChainId, Order, OrderMatching, ChangePubKey, ForcedExit, Token, Transfer, Withdraw, Tokens, \
    EncodedTxValidator
from zklink_sdk.zklink_signer import ZkLinkSigner

PRIVATE_KEY = "336b38ea188a4da28a9a3232a21359a51f6b3c5fdd844c122dd6d76d6605a4ec"

import json


class ZkLinkSignerTest(TestCase):
    def setUp(self):
        self.library = ZkLinkLibrary()

    def test_derive_pub_key(self):
        account = Account.from_key(PRIVATE_KEY)
        signer = ZkLinkSigner.from_account(account, self.library)
        assert signer.public_key.hex() == "b720c6110e673b55b5725dd0ff5778a8668ef4c7324718f78fa11def63081e85"

    def test_change_pubkey_bytes(self):
        tr = ChangePubKey(chain_id=1,
                          fee_token=Token(id=1, address='', symbol='', decimals=18),
                          fee=0, nonce=0, account_id=2, sub_account_id=1, timestamp=1654776640,
                          new_pk_hash='sync:511494921e9aec60dfd65ce125dec96fe7c07133')

        res = "06010000000201511494921e9aec60dfd65ce125dec96fe7c07133000100000000000062a1e340"
        assert tr.encoded_message().hex() == res
        hash = "sync-tx:f43ab3da7afbc99bcd05cfa1b1230e8121791ae7d11726c33a870bf2fd5b36d8"
        assert tr.tx_hash() == hash

    def test_transfer_bytes(self):
        tr = Transfer(from_sub_account_id=1, to_sub_account_id=1,
                      to_address="0xdddd547fA95AdE4EF0C8B517dA7889A5F110eA38",
                      token=Token(id=42, address='', symbol='', decimals=18),
                      amount=1000000000000000000, fee=238000000000000,
                      nonce=3, timestamp=1670830922, account_id=15)

        res = "040000000f01dddd547fa95ade4ef0c8b517da7889a5f110ea3801002a4a817c80081dcc000000036396db4a"
        assert tr.encoded_message().hex() == res
        hash = "sync-tx:f73678d4fa488a846dd89f059c6f2f29b3e79fe27bb162c878e1e0bb39236c17"
        assert tr.tx_hash() == hash

    def test_withdraw_bytes(self):
        tr = Withdraw(to_address="0x3498F456645270eE003441df82C718b56c0e6666",
                      l1_target_token=Token(id=18, address='', symbol='', decimals=18),
                      l2_source_token=Token(id=1, address='', symbol='', decimals=18),
                      amount=100000000000000000000, fee=0, nonce=1, fast_withdraw=0,
                      withdraw_fee_ratio=50, account_id=16, sub_account_id=1, to_chain_id=1,
                      timestamp=1667963443)

        res = "030100000010013498f456645270ee003441df82c718b56c0e66660001001200000000000000056bc75e2d63100000000000000001000032636b1a33"
        assert tr.encoded_message().hex() == res
        hash = "sync-tx:af3da9462520230a29e6c3b72f9da95c015c4b9ca013534f49b867b3fa07ad8d"
        assert tr.tx_hash() == hash

    def test_forced_exit_bytes(self):
        tr = ForcedExit(
            to_chain_id=1, initiator_account_id=1, initiator_sub_account_id=0,
            target="0x3498F456645270eE003441df82C718b56c0e6666", target_sub_account_id=0,
            l2_source_token=Token(id=1, address='', symbol='', decimals=18),
            l1_target_token=Token(id=17, address='', symbol='', decimals=18),
            fee_token=Token(id=1, address='', symbol='', decimals=18),
            fee=4100000000000000, nonce=85, timestamp=1649749979
        )

        res = "070100000001003498f456645270ee003441df82c718b56c0e666600000100110001334d0000005562552fdb"
        assert tr.encoded_message().hex() == res
        hash = "sync-tx:5c0dee07e26608bdc1ce7f66a6fc6eefe58012e17ef38b2f224f23b52f1deca1"
        assert tr.tx_hash() == hash

    def test_pack(self):
        amounts = [0, 1, 2047, 2047000, 1000000000000000000000000000000000]
        for amount in amounts:
            assert closest_packable_transaction_fee(amount) == amount
            assert closest_packable_amount(amount) == amount

    def test_signature(self):
        account = Account.from_key(PRIVATE_KEY)
        signer = ZkLinkSigner.from_account(account, self.library)
        tr = Transfer(from_sub_account_id=1, to_sub_account_id=1,
                      to_address="0xdddd547fA95AdE4EF0C8B517dA7889A5F110eA38",
                      token=Token(id=42, address='', symbol='', decimals=18),
                      amount=1000000000000000000, fee=238000000000000,
                      nonce=3, timestamp=1670830922, account_id=15)

        res = signer.sign_tx(tr)
        assert res.signature == '0ffe0eaef99542f1476c88cb4a0ec0de04382ae9db23070ba299d4dfe9d6a3939356fe614775d837d34c6e5ac3074ecf8ee3ccafab53f8f3d521900930f7af04'

    def test_sign_order(self):
        account = Account.from_key("336b38ea188a4da28a9a3232a21359a51f6b3c5fdd844c122dd6d76d6605a4ec")
        signer = ZkLinkSigner.from_account(account, self.library)
        tr = Order(account_id=6, price=1500000000000000000, amount=100000000000000000000,
                   sub_account_id=1, slot=1, nonce=1,
                   base_token=Token(id=6, address='', symbol='', decimals=18),
                   quote_token=Token(id=7, address='', symbol='', decimals=18),
                   is_sell=0, taker_fee_ratio=10, maker_fee_ratio=5)

        assert signer.private_key.hex() == "03619c4116463a1b9b8ff16a77ad4dd796ac4b9771913152f72be2307f6b35d8"
        res = "ff00000006010001000001000600070000000000000014d1120d7b16000000050a4a817c800a"
        assert tr.encoded_message().hex() == res
        sig = signer.sign_order(tr)
        assert sig.signature == '7e00ed99c8be5e7ac9d9e2e1c5bf8ed6a5e28f1c91a0891d89a0eecd57ea411acc86a9e2073486235c0941b0666d928c109802e2a971571f3a7e845fcc087e01'

    def test_order_matching(self):
        account = Account.from_key("0505050505050505050505050505050505050505050505050505050505050505")
        signer = ZkLinkSigner.from_account(account, self.library)
        maker = Order(account_id=6, price=1500000000000000000, amount=100000000000000000000,
                      sub_account_id=1, slot=1, nonce=1,
                      base_token=Token(id=32, address='', symbol='', decimals=18),
                      quote_token=Token(id=1, address='', symbol='', decimals=18),
                      is_sell=0, taker_fee_ratio=10, maker_fee_ratio=5)
        taker = Order(account_id=6, price=1500000000000000000, amount=1000000000000000000,
                      sub_account_id=1, slot=3, nonce=0,
                      base_token=Token(id=32, address='', symbol='', decimals=18),
                      quote_token=Token(id=1, address='', symbol='', decimals=18),
                      is_sell=1, taker_fee_ratio=10, maker_fee_ratio=5)
        tr = OrderMatching(account_id=6, sub_account_id=1, taker=taker,
                           maker=maker, fee=0,
                           fee_token=Token(id=1, address='', symbol='', decimals=18),
                           expect_base_amount=1000000000000000000,
                           expect_quote_amount=1500000000000000000)

        res = "08000000060183be69c82b2c56df952594436bd024ce85ed2eaee63dadb5b3a3e1aec623880001000000000000000000000de0b6b3a7640000000000000000000014d1120d7b160000"
        assert tr.encoded_message().hex() == res
        sig = signer.sign_order(tr)
        assert sig.signature == 'ec7493d6151fbe1673f8bfefc4f5544b86eeef7010b0bc3500d4036f7e36a0a1e1a31f28015fd27258ad5782c0676b97bda3a4380284903e15eec6b2c7836105'


def check_bytes(a, b):
    res = True
    for i, c in enumerate(a):
        if c != b[i]:
            print(f"Wrong char {i}, {c}, {b[i]}")
            res = False
    assert res
