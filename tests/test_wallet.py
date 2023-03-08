from decimal import Decimal
from fractions import Fraction
from unittest import IsolatedAsyncioTestCase
from zklink_sdk.zklink_provider.types import FeeTxType
from zklink_sdk.types.responses import Fee
import asyncio
from web3 import Account, HTTPProvider, Web3

from zklink_sdk import (EthereumProvider, EthereumSignerWeb3, HttpJsonRPCTransport, Wallet, ZkLink,
                        ZkLinkLibrary, ZkLinkProviderV01, ZkLinkSigner, )
from zklink_sdk.zklink_provider.batch_builder import BatchBuilder
# from zklink_sdk.network import rinkeby
from zklink_sdk.network import testnet
from zklink_sdk.types import ChangePubKeyEcdsa, Token, TransactionWithSignature, \
    TransactionWithOptionalSignature, RatioType, Transfer, AccountTypes
from zklink_sdk.zklink_provider.transaction import TransactionStatus
from zklink_sdk.wallet import DEFAULT_VALID_FROM, DEFAULT_VALID_UNTIL


class TestWallet(IsolatedAsyncioTestCase):
    # 0x995a8b7f96cb837533b79775b6209696d51f435c
    private_key = "0xa045b52470d306ff78e91b0d2d92f90f7504189125a46b69423dc673fd6b4f3e"
    private_keys = [
        # 0x800455ca06265d0cf742086663a527d7c08049fc
        "0x601b47729b2820e94bc10125edc8d534858827428b449175a275069dc00c303f",
        # 0x3aa03b5bcba43eebcb98432507474ffb3423ac94
        "0xa7adf8459b4c9a62f09e0e5390983c0145fa20e88c9e5bf837d8bf3dcd05bd9c",
    ]
    receiver_address = "0x21dDF51966f2A66D03998B0956fe59da1b3a179F"
    forced_exit_account_address = "0x21dDF51966f2A66D03998B0956fe59da1b3aFFFE"
    # nft_transfer_account_address = "0x995a8b7f96cb837533b79775b6209696d51f435c"

    async def get_wallet(self, private_key: str) -> Wallet:
        account = Account.from_key(private_key)
        ethereum_signer = EthereumSignerWeb3(account=account)

        w3 = Web3(HTTPProvider(
            endpoint_uri="https://rinkeby.infura.io/v3/bcf42e619a704151a1b0d95a35cb2e62"))
        provider = ZkLinkProviderV01(provider=HttpJsonRPCTransport(network=testnet))
        address = await provider.get_contract_address()
        zklink = ZkLink(account=account, web3=w3, zklink_contract_address=address.main_contract)
        ethereum_provider = EthereumProvider(w3, zklink)
        signer = ZkLinkSigner.from_account(account, self.library)

        return Wallet(ethereum_provider=ethereum_provider, zk_signer=signer,
                      eth_signer=ethereum_signer, provider=provider)

    async def asyncSetUp(self):
        self.library = ZkLinkLibrary()
        self.wallet = await self.get_wallet(self.private_key)
        self.wallets = [await self.get_wallet(key) for key in self.private_keys]

    async def test_get_account_state(self):
        data = await self.wallet.zk_provider.get_state(self.wallet.address())
        assert data.address.lower() == self.wallet.address().lower()

    async def test_deposit(self):
        token = await self.wallet.resolve_token("USDT")
        await self.wallet.ethereum_provider.approve_deposit(token, Decimal(1))

        res = await self.wallet.ethereum_provider.deposit(token, Decimal(1),
                                                          self.wallet.address())
        assert res

    async def test_change_pubkey(self):
        trans = await self.wallet.set_signing_key("ETH", eth_auth_data=ChangePubKeyEcdsa())
        try:
            result = await trans.await_committed(attempts=1000, attempts_timeout=1000)
            self.assertEqual(result.status, TransactionStatus.COMMITTED)
        except Exception as ex:
            assert False, str(ex)

    async def test_is_public_key_onset(self):
        pubkey_hash = self.wallet.zk_signer.pubkey_hash()
        nonce = await self.wallet.zk_provider.get_account_nonce(self.wallet.address())
        await self.wallet.ethereum_provider.set_auth_pubkey_hash(pubkey_hash, nonce)
        assert await self.wallet.ethereum_provider.is_onchain_auth_pubkey_hash_set(nonce)

    async def test_transfer(self):
        tr = await self.wallet.transfer(self.receiver_address,
                                        amount=Decimal("0.01"), token="USDC")
        try:
            result = await tr.await_committed(attempts=20, attempts_timeout=100)
            self.assertEqual(result.status, TransactionStatus.COMMITTED)
        except Exception as ex:
            assert False, str(ex)

    # async def test_batch(self):
    #     trs = []
    #     eth_token = await self.wallet.resolve_token("ETH")
    #     fee = (await self.wallet.zk_provider.get_transaction_fee(
    #         FeeTxType.transfer, self.receiver_address, "ETH"
    #     )).total_fee
    #     nonce = await self.wallet.zk_provider.get_account_nonce(self.wallet.address())
    #
    #     for i in range(3):
    #         tr, sig = await self.wallet.build_transfer(
    #             self.receiver_address,
    #             amount=1, token=eth_token, fee=fee, nonce=nonce + i)
    #         trs.append(TransactionWithSignature(tr, sig))
    #     res = await self.wallet.send_txs_batch(trs)
    #     self.assertEqual(len(res), 3)
    #     for i, tr in enumerate(res):
    #         try:
    #             result = await tr.await_committed(attempts=100, attempts_timeout=500)
    #             self.assertEqual(result.status, TransactionStatus.COMMITTED)
    #         except Exception as ex:
    #             assert False, f"test_batch, getting transaction {i}  result has failed with error: {ex}"

    # async def test_build_batch_transfer(self):
    #     nonce = await self.wallet.zk_provider.get_account_nonce(self.wallet.address())
    #     builder = BatchBuilder.from_wallet(self.wallet, nonce)
    #     for i in range(2):
    #         builder.add_transfer(self.receiver_address, "ETH", Decimal("0.00005"))
    #     build_result = await builder.build()
    #     print(f"Total fees: {build_result.total_fees}")
    #     transactions = await self.wallet.zk_provider.submit_batch_builder_txs_batch(build_result.transactions,
    #                                                                                 build_result.signature)
    #     for i, tran in enumerate(transactions):
    #         try:
    #             result = await tran.await_committed(attempts=1000, attempts_timeout=1000)
    #             self.assertEqual(result.status, TransactionStatus.COMMITTED)
    #         except Exception as ex:
    #             assert False, f"test_build_batch_transfer, transaction {i} " \
    #                           f"has failed with error: {ex}"

    # async def test_build_batch_change_pub_key(self):
    #     nonce = await self.wallet.zk_provider.get_account_nonce(self.wallet.address())
    #     builder = BatchBuilder.from_wallet(self.wallet, nonce)
    #     builder.add_change_pub_key("ETH", eth_auth_type=ChangePubKeyEcdsa())
    #     builder.add_transfer(self.receiver_address, "USDT", Decimal("0.001"))
    #     build_result = await builder.build()
    #     print(f"Total fees: {build_result.total_fees}")
    #     transactions = await self.wallet.zk_provider.submit_batch_builder_txs_batch(build_result.transactions,
    #                                                                                 build_result.signature)
    #     self.assertEqual(len(transactions), 2)
    #     for i, tran in enumerate(transactions):
    #         try:
    #             result = await tran.await_committed(attempts=100, attempts_timeout=1000)
    #             self.assertEqual(result.status, TransactionStatus.COMMITTED)
    #         except Exception as ex:
    #             assert False, f"test_build_batch_change_pub_key, transaction {i} " \
    #                           f"has failed with error: {ex}"

    # async def test_build_batch_withdraw(self):
    #     nonce = await self.wallet.zk_provider.get_account_nonce(self.wallet.address())
    #     builder = BatchBuilder.from_wallet(self.wallet, nonce)
    #     builder.add_withdraw(self.receiver_address,
    #                          "USDT",
    #                          Decimal("0.000001")
    #                          )
    #     build_result = await builder.build()
    #     print(f"Total fees: {build_result.total_fees}")
    #     transactions = await self.wallet.zk_provider.submit_batch_builder_txs_batch(build_result.transactions,
    #                                                                                 build_result.signature)
    #     self.assertEqual(len(transactions), 1)
    #
    #     try:
    #         result = await transactions[0].await_committed(attempts=100, attempts_timeout=1000)
    #         self.assertEqual(result.status, TransactionStatus.COMMITTED)
    #     except Exception as ex:
    #         assert False, f"test_build_batch_withdraw, transaction has failed with error: {ex}"

    async def test_forced_exit(self):
        result_transaction = await self.wallet.transfer(self.forced_exit_account_address, Decimal("0.1"), "USDC")
        result = await result_transaction.await_committed()
        self.assertEqual(result.status, TransactionStatus.COMMITTED)
        tr = await self.wallet.forced_exit(self.forced_exit_account_address, "USDC")
        try:
            result = await tr.await_verified(attempts=10, attempts_timeout=1000)
            self.assertEqual(result.status, TransactionStatus.COMMITTED)
        except Exception as ex:
            assert False, f"test_forced_exit, getting transaction result has failed with error: {result.error_message}"

    async def test_withdraw(self):
        tr = await self.wallet.withdraw(self.receiver_address,
                                        Decimal("0.000001"), "USDT")
        try:
            result = await tr.await_committed(attempts=30, attempts_timeout=100)
            self.assertEqual(result.status, TransactionStatus.COMMITTED)
        except Exception as ex:
            assert False, f"test_withdraw, transaction has failed with error: {ex}"

    async def test_get_tokens(self):
        tokens = await self.wallet.zk_provider.get_tokens()
        assert tokens.find_by_symbol("ETH")

    async def test_is_signing_key_set(self):
        assert await self.wallet.is_signing_key_set()

    async def test_toggle_2fa(self):
        """
        Relate to the server-side code it must be Owned type if enable_2fa is passed
        let new_type = if toggle_2fa.enable {
            EthAccountType::Owned
        } else {
            EthAccountType::No2FA
        };
        """
        result = await self.wallet.enable_2fa()
        self.assertTrue(result)
        account_state = await self.wallet.get_account_state()
        self.assertEqual(AccountTypes.OWNED, account_state.account_type)

        pub_key_hash = self.wallet.zk_signer.pubkey_hash_str()
        result = await self.wallet.disable_2fa(pub_key_hash)
        self.assertTrue(result)
        account_state = await self.wallet.get_account_state()
        self.assertEqual(AccountTypes.NO_2FA, account_state.account_type)


class TestEthereumProvider(IsolatedAsyncioTestCase):
    private_key = "0xa045b52470d306ff78e91b0d2d92f90f7504189125a46b69423dc673fd6b4f3e"

    async def asyncSetUp(self) -> None:
        self.account = Account.from_key(self.private_key)
        self.library = ZkLinkLibrary()

        w3 = Web3(HTTPProvider(
            endpoint_uri="https://rinkeby.infura.io/v3/bcf42e619a704151a1b0d95a35cb2e62"))
        provider = ZkLinkProviderV01(provider=HttpJsonRPCTransport(network=testnet))
        address = await provider.get_contract_address()
        self.zklink = ZkLink(account=self.account, web3=w3,
                             zklink_contract_address=address.main_contract)
        self.ethereum_provider = EthereumProvider(w3, self.zklink)

    async def test_approve_deposit(self):
        token = Token(
            address=Web3.toChecksumAddress('0xeb8f08a975ab53e34d8a0330e0d34de942c95926'),
            id=20, symbol='USDC',
            decimals=18)
        assert await self.ethereum_provider.approve_deposit(token, Decimal(1))

    async def test_full_exit(self):
        token = Token(
            address=Web3.toChecksumAddress('0xD2084eA2AE4bBE1424E4fe3CDE25B713632fb988'),
            id=20, symbol='BAT',
            decimals=18)
        assert await self.ethereum_provider.full_exit(token, 6713)

    async def test_is_deposit_approved(self):
        token = Token(
            address=Web3.toChecksumAddress('0xD2084eA2AE4bBE1424E4fe3CDE25B713632fb988'),
            id=20, symbol='BAT',
            decimals=18)
        assert await self.ethereum_provider.is_deposit_approved(token, 1)


class TestZkLinkProvider(IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.provider = ZkLinkProviderV01(provider=HttpJsonRPCTransport(network=testnet))

    # async def test_get_token_price(self):
    #     tokens = await self.provider.get_tokens()
    #     price = await self.provider.get_token_price(tokens.find_by_symbol("USDC"))
    #     self.assertAlmostEqual(float(price), 1.0, delta=0.2)
