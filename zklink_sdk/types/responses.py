from typing import Any, Dict, Optional, List
from enum import Enum
from decimal import Decimal
from zklink_sdk.types.transactions import Token

from pydantic import BaseModel


def to_camel(string: str) -> str:
    first, *others = string.split('_')
    return ''.join([first.lower(), *map(str.title, others)])


class Balance(BaseModel):
    amount: int
    expected_accept_block: int

    class Config:
        alias_generator = to_camel


class Depositing(BaseModel):
    balances: Dict[str, Balance]


class State(BaseModel):
    nonce: int
    pub_key_hash: str
    balances: Dict[str, int]

    class Config:
        alias_generator = to_camel


class AccountTypes(str, Enum):
    OWNED = "Owned",
    CREATE2 = "CREATE2",
    NO_2FA = "No2FA"


class AccountState(BaseModel):
    address: str
    id: Optional[int]
    account_type: Optional[AccountTypes]
    pub_key_hash: str
    nonce: int

    # depositing: Optional[Depositing]
    # committed: Optional[State]
    # verified: Optional[State]

    class Config:
        alias_generator = to_camel

    def get_nonce(self) -> int:
        # assert self.committed is not None, "`get_nonce` needs `committed` to be set"
        # return self.committed.nonce
        return self.nonce


class Fee(BaseModel):
    fee_type: Any
    gas_tx_amount: int
    gas_price_wei: int
    gas_fee: int
    zkp_fee: int
    total_fee: int

    class Config:
        alias_generator = to_camel


class ContractAddress(BaseModel):
    chain_id: int
    layer1_chain_id: int
    main_contract: str
    gov_contract: str

    class Config:
        alias_generator = to_camel


class ContractAddresses(BaseModel):
    addresses: List[ContractAddress]

    def find_by_address(self, main_contract: str) -> Optional[ContractAddress]:
        found_address = [address for address in self.addresses if address.main_contract == main_contract]
        if found_address:
            return found_address[0]
        else:
            return None

    def find_by_chain_id(self, chain_id: int) -> Optional[ContractAddress]:
        found_address = [address for address in self.addresses if address.chain_id == chain_id]
        if found_address:
            return found_address[0]
        else:
            return None


class BlockInfo(BaseModel):
    block_number: int
    committed: bool
    verified: bool

    class Config:
        alias_generator = to_camel


class TransactionDetails(BaseModel):
    executed: bool
    success: bool
    fail_reason: Optional[str] = None
    block: BlockInfo

    class Config:
        alias_generator = to_camel
