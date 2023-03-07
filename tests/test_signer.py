from unittest import TestCase
from fractions import Fraction

from web3 import Account

from zklink_sdk import ZkLinkLibrary, EthereumSignerWeb3
from zklink_sdk.serializers import closest_packable_amount, closest_packable_transaction_fee
from zklink_sdk.types import ChainId, ChangePubKey, ForcedExit, Token, Transfer, Withdraw, MintNFT, WithdrawNFT, Order, \
    Swap, Tokens, EncodedTxValidator
from zklink_sdk.zklink_signer import ZkLinkSigner

PRIVATE_KEY = "336b38ea188a4da28a9a3232a21359a51f6b3c5fdd844c122dd6d76d6605a4ec"

import json


class ZkLinkSignerTest(TestCase):
    def setUp(self):
        self.library = ZkLinkLibrary()

    def test_derive_pub_key(self):
        account = Account.from_key(PRIVATE_KEY)
        # signer = ZkLinkSigner.from_account(account, self.library, ChainId.MAINNET)
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

    # def test_order_bytes(self):
    #     token1 = Token.eth()
    #     token2 = Token(id=2, symbol='', address='', decimals=0)  # only id matters
    #     order = Order(account_id=6, nonce=18, token_sell=token1, token_buy=token2,
    #                   ratio=Fraction(1, 2), amount=1000000,
    #                   recipient='0x823b6a996cea19e0c41e250b20e2e804ea72ccdf',
    #                   valid_from=0, valid_until=4294967295)
    #     res = '6f0100000006823b6a996cea19e0c41e250b20e2e804ea72ccdf0000001200000000000000020000000000000000000000000000010000000000000000000000000000020001e84800000000000000000000000000ffffffff'
    #     assert order.encoded_message().hex() == res

    # def test_swap_bytes(self):
    #     token1 = Token(id=1, symbol='', address='', decimals=0)  # only id matters
    #     token2 = Token(id=2, symbol='', address='', decimals=0)  # only id matters
    #     token3 = Token(id=3, symbol='', address='', decimals=0)  # only id matters
    #     order1 = Order(account_id=6, nonce=18, token_sell=token1, token_buy=token2,
    #                    ratio=Fraction(1, 2), amount=1000000,
    #                    recipient='0x823b6a996cea19e0c41e250b20e2e804ea72ccdf',
    #                    valid_from=0, valid_until=4294967295)
    #     order2 = Order(account_id=44, nonce=101, token_sell=token2, token_buy=token1,
    #                    ratio=Fraction(3, 1), amount=2500000,
    #                    recipient='0x63adbb48d1bc2cf54562910ce54b7ca06b87f319',
    #                    valid_from=0, valid_until=4294967295)
    #     swap = Swap(orders=(order1, order2), nonce=1, amounts=(1000000, 2500000),
    #                 submitter_id=5, submitter_address="0xedE35562d3555e61120a151B3c8e8e91d83a378a",
    #                 fee_token=token3, fee=123)
    #     res = "f40100000005ede35562d3555e61120a151b3c8e8e91d83a378a000000017b1e76f6f124bae1917435a02cfbf5571d79ddb8380bc4bf4858c9e9969487000000030f600001e848000004c4b400"
    #     assert swap.encoded_message().hex() == res

    # def test_order_deserialization(self):
    #     token1 = Token(id=1, symbol='', address='', decimals=0)  # only id matters
    #     token2 = Token(id=2, symbol='', address='', decimals=0)  # only id matters
    #     tokens = Tokens(tokens=[token1, token2])
    #
    #     order = Order(account_id=7, nonce=18, token_sell=token1, token_buy=token2,
    #                   ratio=Fraction(1, 4), amount=1000000,
    #                   recipient='0x823b6a996cea19e0c41e250b20e2e804ea72ccdf',
    #                   valid_from=0, valid_until=4294967295)
    #     serialized_order = order.dict()
    #     from_json_order = Order.from_json(serialized_order, tokens)
    #     self.assertEqual(order.account_id, from_json_order.account_id)
    #     self.assertEqual(order.nonce, from_json_order.nonce)
    #     self.assertEqual(order.token_sell, from_json_order.token_sell)
    #     self.assertEqual(order.token_buy, from_json_order.token_buy)
    #     self.assertEqual(order.ratio, from_json_order.ratio)
    #     self.assertEqual(order.recipient, from_json_order.recipient)
    #     self.assertEqual(order.valid_from, from_json_order.valid_from)
    #     self.assertEqual(order.valid_until, from_json_order.valid_until)

    # def test_order_zklink_signature_checking(self):
    #     account = Account.from_key(PRIVATE_KEY)
    #     # signer = ZkLinkSigner.from_account(account, self.library, ChainId.MAINNET)
    #     signer = ZkLinkSigner.from_account(account, self.library)
    #
    #     token1 = Token(id=1, symbol='', address='', decimals=0)  # only id matters
    #     token2 = Token(id=2, symbol='', address='', decimals=0)  # only id matters
    #     tokens_pool = Tokens(tokens=[token1, token2])
    #
    #     order = Order(account_id=7, nonce=18, token_sell=token1, token_buy=token2,
    #                   ratio=Fraction(1, 4), amount=1000000,
    #                   recipient='0x823b6a996cea19e0c41e250b20e2e804ea72ccdf',
    #                   valid_from=0, valid_until=4294967295)
    #
    #     order.signature = signer.sign_tx(order)
    #
    #     validator = EncodedTxValidator(self.library)
    #     serialized_order = json.dumps(order.dict(), indent=4)
    #     print(f"json : {serialized_order}")
    #     deserialized_order = Order.from_json(json.loads(serialized_order), tokens_pool)
    #     ret = validator.is_valid_signature(deserialized_order)
    #     self.assertTrue(ret)

    # def test_is_valid_order_deserialized(self):
    #     account = Account.from_key(PRIVATE_KEY)
    #     # zklink_signer = ZkLinkSigner.from_account(account, self.library, ChainId.MAINNET)
    #     zklink_signer = ZkLinkSigner.from_account(account, self.library)
    #     ethereum_signer = EthereumSignerWeb3(account=account)
    #
    #     token1 = Token(id=1, symbol='', address='', decimals=0)  # only id matters
    #     token2 = Token(id=2, symbol='', address='', decimals=0)  # only id matters
    #     tokens_pool = Tokens(tokens=[token1, token2])
    #
    #     order = Order(account_id=7, nonce=18, token_sell=token1, token_buy=token2,
    #                   ratio=Fraction(1, 4), amount=1000000,
    #                   recipient='0x823b6a996cea19e0c41e250b20e2e804ea72ccdf',
    #                   valid_from=0, valid_until=4294967295)
    #     order.signature = zklink_signer.sign_tx(order)
    #     order.eth_signature = ethereum_signer.sign_tx(order)
    #     zklink_validator = EncodedTxValidator(self.library)
    #     serialized_order = json.dumps(order.dict(), indent=4)
    #
    #     deserialized_order = Order.from_json(json.loads(serialized_order), tokens_pool)
    #     ret = zklink_validator.is_valid_signature(deserialized_order)
    #     self.assertTrue(ret)
    #     ret = deserialized_order.is_valid_eth_signature(ethereum_signer.address())
    #     self.assertTrue(ret)

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

    # def test_mint_nft_bytes(self):
    #     tr = MintNFT(
    #         creator_id=44,
    #         creator_address="0xedE35562d3555e61120a151B3c8e8e91d83a378a",
    #         content_hash="0000000000000000000000000000000000000000000000000000000000000123",
    #         recipient="0x19aa2ed8712072e918632259780e587698ef58df",
    #         fee=1000000,
    #         fee_token=Token.eth(),
    #         nonce=12
    #     )
    #     res = "f6010000002cede35562d3555e61120a151b3c8e8e91d83a378a000000000000000000000000000000000000000000000000000000000000012319aa2ed8712072e918632259780e587698ef58df000000007d030000000c"
    #     assert tr.encoded_message().hex() == res

    # def test_withdraw_nft_bytes(self):
    #     tr = WithdrawNFT(
    #         account_id=44,
    #         from_address="0xedE35562d3555e61120a151B3c8e8e91d83a378a",
    #         to_address="0x19aa2ed8712072e918632259780e587698ef58df",
    #         fee_token=Token.eth(),
    #         fee=1000000,
    #         nonce=12,
    #         valid_from=0,
    #         valid_until=4294967295,
    #         token_id=100000
    #     )
    #     res = "f5010000002cede35562d3555e61120a151b3c8e8e91d83a378a19aa2ed8712072e918632259780e587698ef58df000186a0000000007d030000000c000000000000000000000000ffffffff"
    #     assert tr.encoded_message().hex() == res

    def test_pack(self):
        amounts = [0, 1, 2047, 2047000, 1000000000000000000000000000000000]
        for amount in amounts:
            assert closest_packable_transaction_fee(amount) == amount
            assert closest_packable_amount(amount) == amount

    def test_signature(self):
        account = Account.from_key(PRIVATE_KEY)
        # signer = ZkLinkSigner.from_account(account, self.library, ChainId.MAINNET)
        signer = ZkLinkSigner.from_account(account, self.library)
        tr = Transfer(from_sub_account_id=1, to_sub_account_id=1,
                      to_address="0xdddd547fA95AdE4EF0C8B517dA7889A5F110eA38",
                      token=Token(id=42, address='', symbol='', decimals=18),
                      amount=1000000000000000000, fee=238000000000000,
                      nonce=3, timestamp=1670830922, account_id=15)
        res = signer.sign_tx(tr)
        assert res.signature == '0ffe0eaef99542f1476c88cb4a0ec0de04382ae9db23070ba299d4dfe9d6a3939356fe614775d837d34c6e5ac3074ecf8ee3ccafab53f8f3d521900930f7af04'


def check_bytes(a, b):
    res = True
    for i, c in enumerate(a):
        if c != b[i]:
            print(f"Wrong char {i}, {c}, {b[i]}")
            res = False
    assert res
