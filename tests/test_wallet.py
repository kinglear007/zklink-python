from decimal import Decimal
from unittest import IsolatedAsyncioTestCase
from zklink_sdk.zklink_provider.types import FeeTxType
from zklink_sdk.types.responses import Fee
import asyncio
from web3 import Account, HTTPProvider, Web3

from zklink_sdk import (EthereumProvider, EthereumSignerWeb3, HttpJsonRPCTransport, Wallet, ZkLink,
                        ZkLinkLibrary, ZkLinkProviderV01, ZkLinkSigner, )
from zklink_sdk.network import testnet, devnet
from zklink_sdk.types import ChangePubKeyEcdsa, Token, TransactionWithSignature, \
    TransactionWithOptionalSignature, RatioType, Transfer, AccountTypes
from zklink_sdk.zklink_provider.transaction import TransactionStatus


class TestWallet(IsolatedAsyncioTestCase):
    # 0x995a8b7f96cb837533b79775b6209696d51f435c
    private_key = "0xa045b52470d306ff78e91b0d2d92f90f7504189125a46b69423dc673fd6b4f3e"
    receiver_address = "0x21dDF51966f2A66D03998B0956fe59da1b3a179F"
    forced_exit_account_address = "0x21dDF51966f2A66D03998B0956fe59da1b3aFFFE"

    async def get_wallet(self, private_key: str) -> Wallet:
        account = Account.from_key(private_key)
        ethereum_signer = EthereumSignerWeb3(account=account)

        w3 = Web3(HTTPProvider(
            endpoint_uri=devnet.zklink_url))
        provider = ZkLinkProviderV01(provider=HttpJsonRPCTransport(network=testnet))
        addresses = await provider.get_support_chains()
        address = addresses.find_by_chain_id(1)
        zklink = ZkLink(account=account, web3=w3, zklink_contract_address=address.main_contract)
        ethereum_provider = EthereumProvider(w3, zklink)
        signer = ZkLinkSigner.from_account(account, self.library)

        return Wallet(ethereum_provider=ethereum_provider, zk_signer=signer,
                      eth_signer=ethereum_signer, provider=provider)

    async def asyncSetUp(self):
        self.library = ZkLinkLibrary()
        self.wallet = await self.get_wallet(self.private_key)

    async def test_get_account_state(self):
        data = await self.wallet.zk_provider.get_account(self.wallet.address())
        assert data.address.lower() == self.wallet.address().lower()

    async def test_deposit(self):
        token = Token(symbol="USDT", id=0, address="", chain_id=1, decimals=18)
        await self.wallet.ethereum_provider.approve_deposit(token, Decimal(1))

        res = await self.wallet.ethereum_provider.deposit(token, Decimal(1),
                                                          self.wallet.address())
        assert res

    async def test_change_pubkey(self):
        trans = await self.wallet.change_pubkey(chain_id=1,
                                                fee_token=Token(symbol="ETH", id=0, address="", chain_id=1,
                                                                decimals=18),
                                                sub_account_id=1,
                                                eth_auth_data=ChangePubKeyEcdsa())
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
        tr = await self.wallet.transfer(from_sub_account_id=1, to=self.receiver_address, to_sub_account_id=1,
                                        amount=Decimal("0.01"),
                                        token=Token(symbol="USDC", id=0, address="", chain_id=1, decimals=18))
        try:
            result = await tr.await_committed(attempts=20, attempts_timeout=100)
            self.assertEqual(result.status, TransactionStatus.COMMITTED)
        except Exception as ex:
            assert False, str(ex)

    async def test_forced_exit(self):
        result_transaction = await self.wallet.transfer(from_sub_account_id=1, to=self.forced_exit_account_address,
                                                        to_sub_account_id=1,
                                                        amount=Decimal("0.1"),
                                                        token=Token(symbol="USDC", id=0, address="", chain_id=1,
                                                                    decimals=18))
        result = await result_transaction.await_committed()
        self.assertEqual(result.status, TransactionStatus.COMMITTED)
        tr = await self.wallet.forced_exit(to_chain_id=2, initiator_sub_account_id=1,
                                           target=self.forced_exit_account_address, target_sub_account_id=1,
                                           l2_source_token=Token(symbol="USD", id=1, address="", chain_id=1,
                                                                 decimals=18),
                                           l1_target_token=Token(symbol="USDC", id=18, address="", chain_id=2,
                                                                 decimals=18),
                                           fee_token=Token(symbol="USD", id=1, address="", chain_id=1,
                                                           decimals=18))
        try:
            result = await tr.await_verified(attempts=10, attempts_timeout=1000)
            self.assertEqual(result.status, TransactionStatus.COMMITTED)
        except Exception as ex:
            assert False, f"test_forced_exit, getting transaction result has failed with error: {result.error_message}"

    async def test_withdraw(self):
        tr = await self.wallet.withdraw(to_chain_id=2, sub_account_id=1, eth_address=self.receiver_address,
                                        amount=Decimal("0.000001"),
                                        l2_source_token=Token(symbol="USD", id=1, address="", chain_id=1, decimals=18),
                                        l1_target_token=Token(symbol="USDC", id=18, address="", chain_id=1,
                                                              decimals=18),
                                        fast_withdraw=1, withdraw_fee_ratio=50)
        try:
            result = await tr.await_committed(attempts=30, attempts_timeout=100)
            self.assertEqual(result.status, TransactionStatus.COMMITTED)
        except Exception as ex:
            assert False, f"test_withdraw, transaction has failed with error: {ex}"

    async def test_get_tokens(self):
        tokens = await self.wallet.zk_provider.get_support_tokens()
        assert tokens.find_by_symbol("wETH", 1)

    async def test_is_signing_key_set(self):
        assert await self.wallet.is_signing_key_set()


class TestEthereumProvider(IsolatedAsyncioTestCase):
    private_key = "0xa045b52470d306ff78e91b0d2d92f90f7504189125a46b69423dc673fd6b4f3e"

    async def asyncSetUp(self) -> None:
        self.account = Account.from_key(self.private_key)
        self.library = ZkLinkLibrary()

        w3 = Web3(HTTPProvider(
            endpoint_uri=devnet.zklink_url))
        provider = ZkLinkProviderV01(provider=HttpJsonRPCTransport(network=testnet))
        addresses = await provider.get_support_chains()
        address = addresses.find_by_chain_id(1)
        self.zklink = ZkLink(account=self.account, web3=w3,
                             zklink_contract_address=address.main_contract)
        self.ethereum_provider = EthereumProvider(w3, self.zklink)

    async def test_approve_deposit(self):
        token = Token(
            address=Web3.toChecksumAddress('0xeb8f08a975ab53e34d8a0330e0d34de942c95926'),
            id=20, chain_id=0, symbol='USDC',
            decimals=18)
        assert await self.ethereum_provider.approve_deposit(token, Decimal(1))

    async def test_full_exit(self):
        token = Token(
            address=Web3.toChecksumAddress('0xD2084eA2AE4bBE1424E4fe3CDE25B713632fb988'),
            id=20, chain_id=0, symbol='BAT',
            decimals=18)
        assert await self.ethereum_provider.full_exit(token, 6713)

    async def test_is_deposit_approved(self):
        token = Token(
            address=Web3.toChecksumAddress('0xD2084eA2AE4bBE1424E4fe3CDE25B713632fb988'),
            id=20, chain_id=0, symbol='BAT',
            decimals=18)
        assert await self.ethereum_provider.is_deposit_approved(token, 1)


class TestZkLinkProvider(IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.provider = ZkLinkProviderV01(provider=HttpJsonRPCTransport(network=testnet))
