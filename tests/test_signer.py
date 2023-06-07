from unittest import TestCase

from web3 import Account

from zklink_sdk import ZkLinkLibrary
from zklink_sdk.serializers import closest_packable_amount, closest_packable_transaction_fee
from zklink_sdk.types import Order, OrderMatching, ChangePubKey, ForcedExit, Token, Transfer, Withdraw
from zklink_sdk.zklink_signer import ZkLinkSigner

PRIVATE_KEY = "336b38ea188a4da28a9a3232a21359a51f6b3c5fdd844c122dd6d76d6605a4ec"


class ZkLinkSignerTest(TestCase):
    def setUp(self):
        self.library = ZkLinkLibrary()

    def test_derive_pub_key(self):
        account = Account.from_key(PRIVATE_KEY)
        signer = ZkLinkSigner.from_account(account, self.library)
        assert signer.public_key.hex() == "a7fa694539b011497b6da221255e38c7a22d49731e4db3d4b3b5ca858fc07404"

    def test_change_pubkey_bytes(self):
        tr = ChangePubKey(chain_id=1,
                          fee_token=Token(id=1, chain_id=0, address='', symbol='', decimals=18),
                          fee=0, nonce=0, account_id=2, sub_account_id=1, timestamp=1654776640,
                          new_pk_hash='0x511494921e9aec60dfd65ce125dec96fe7c07133')

        res = "06010000000201000000000000000000000000511494921e9aec60dfd65ce125dec96fe7c07133000100000000000062a1e340"
        assert tr.encoded_message().hex() == res
        hash = "0x2b015d3c2156f70208f10b6a8194fbe76a5d4ddde770421ff61d98dadecf82e2"
        assert tr.tx_hash() == hash

    def test_transfer_bytes(self):
        tr = Transfer(from_sub_account_id=1, to_sub_account_id=1,
                      to_address="0xdddd547fA95AdE4EF0C8B517dA7889A5F110eA38",
                      token=Token(id=42, chain_id=0, address='', symbol='', decimals=18),
                      amount=1000000000000000000, fee=238000000000000,
                      nonce=3, timestamp=1670830922, account_id=15)

        res = "040000000f01000000000000000000000000dddd547fa95ade4ef0c8b517da7889a5f110ea3801002a4a817c80081dcc000000036396db4a"
        assert tr.encoded_message().hex() == res
        hash = "0xb5bf0377f1cf680a08714aa23d5b95bb4f5576e0bb3a339aab6d76594434b2d1"
        assert tr.tx_hash() == hash

    def test_withdraw_bytes(self):
        tr = Withdraw(to_address="0x3498F456645270eE003441df82C718b56c0e6666",
                      l1_target_token=Token(id=18, chain_id=0, address='', symbol='', decimals=18),
                      l2_source_token=Token(id=1, chain_id=0, address='', symbol='', decimals=18),
                      amount=100000000000000000000, fee=0, nonce=1, fast_withdraw=0,
                      withdraw_fee_ratio=50, account_id=16, sub_account_id=1, to_chain_id=1,
                      timestamp=1667963443)

        res = "030100000010010000000000000000000000003498f456645270ee003441df82c718b56c0e66660001001200000000000000056bc75e2d63100000000000000001000032636b1a33"
        assert tr.encoded_message().hex() == res
        hash = "0x0d0308f53c60a2b03b613619aa5fce3c793e55d72b7e7d64a677a1dd203fac5a"
        assert tr.tx_hash() == hash

    def test_forced_exit_bytes(self):
        tr = ForcedExit(
            to_chain_id=1, initiator_account_id=1, initiator_sub_account_id=0,
            target="0x3498F456645270eE003441df82C718b56c0e6666", target_sub_account_id=0,
            l2_source_token=Token(id=1, chain_id=0, address='', symbol='', decimals=18),
            l1_target_token=Token(id=17, chain_id=0, address='', symbol='', decimals=18),
            fee_token=Token(id=1, chain_id=0, address='', symbol='', decimals=18),
            fee=4100000000000000, nonce=85, timestamp=1649749979
        )

        res = "070100000001000000000000000000000000003498f456645270ee003441df82c718b56c0e666600000100110001334d0000005562552fdb"
        assert tr.encoded_message().hex() == res
        hash = "0x48b25e383fd609d1180f21a713ae3084457269878ada1cfa25434cb226ab93ce"
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
                      token=Token(id=42, chain_id=0, address='', symbol='', decimals=18),
                      amount=1000000000000000000, fee=238000000000000,
                      nonce=3, timestamp=1670830922, account_id=15)

        res = signer.sign_tx(tr)
        assert res.signature == 'fbfa2b7452f71b03a5d0eb588bbe69d7c0899686ccb74acf67104567a312bba8ca510bf4bd34b245cd8aba54229612aa9eeafc1f6a018573edef01ee26c09f02'

    def test_sign_order(self):
        account = Account.from_key("336b38ea188a4da28a9a3232a21359a51f6b3c5fdd844c122dd6d76d6605a4ec")
        signer = ZkLinkSigner.from_account(account, self.library)
        tr = Order(account_id=6, price=1500000000000000000, amount=100000000000000000000,
                   sub_account_id=1, slot=1, nonce=1,
                   base_token=Token(id=6, chain_id=0, address='', symbol='', decimals=18),
                   quote_token=Token(id=7, chain_id=0, address='', symbol='', decimals=18),
                   is_sell=0, taker_fee_ratio=10, maker_fee_ratio=5)

        assert signer.private_key.hex() == "02b9a5696ea4dfa045162303fdd6de20a41a0beedc2dee2d29a023f9058b9b5a"
        res = "ff00000006010001000001000600070000000000000014d1120d7b16000000050a4a817c800a"
        assert tr.encoded_message().hex() == res
        sig = signer.sign_order(tr)
        assert sig.signature == 'a847e994b249c12e93105fa4e3a2200bceca5686911e658a6298b0dc8109142641d5981868cc3cde5731a7a1cf816342284e192da8bf941e592bf56491f74400'

    def test_order_matching(self):
        account = Account.from_key("0505050505050505050505050505050505050505050505050505050505050505")
        signer = ZkLinkSigner.from_account(account, self.library)
        maker = Order(account_id=6, price=1500000000000000000, amount=100000000000000000000,
                      sub_account_id=1, slot=1, nonce=1,
                      base_token=Token(id=32, chain_id=0, address='', symbol='', decimals=18),
                      quote_token=Token(id=1, chain_id=0, address='', symbol='', decimals=18),
                      is_sell=0, taker_fee_ratio=10, maker_fee_ratio=5)
        taker = Order(account_id=6, price=1500000000000000000, amount=1000000000000000000,
                      sub_account_id=1, slot=3, nonce=0,
                      base_token=Token(id=32, chain_id=0, address='', symbol='', decimals=18),
                      quote_token=Token(id=1, chain_id=0, address='', symbol='', decimals=18),
                      is_sell=1, taker_fee_ratio=10, maker_fee_ratio=5)
        tr = OrderMatching(account_id=6, sub_account_id=1, taker=taker,
                           maker=maker, fee=0,
                           fee_token=Token(id=1, chain_id=0, address='', symbol='', decimals=18),
                           expect_base_amount=1000000000000000000,
                           expect_quote_amount=1500000000000000000)

        res = "08000000060183be69c82b2c56df952594436bd024ce85ed2eaee63dadb5b3a3e1aec623880001000000000000000000000de0b6b3a7640000000000000000000014d1120d7b160000"
        assert tr.encoded_message().hex() == res
        sig = signer.sign_tx(tr)
        assert sig.signature == '7f8126c3e032cba9f0877f0ad7016b4c14e7171de50aa387f97f89611f2a11976a8ff34ed3bfa1678b52365416f62d9a4f94e29026cb1f23e0d81335c87f6601'


def check_bytes(a, b):
    res = True
    for i, c in enumerate(a):
        if c != b[i]:
            print(f"Wrong char {i}, {c}, {b[i]}")
            res = False
    assert res
