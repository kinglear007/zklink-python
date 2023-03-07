from enum import IntEnum

from .responses import *
from .signatures import *
from .transactions import *
from .auth_types import *


class ChainId(IntEnum):
    MAINNET = 1


class SubAccountId(IntEnum):
    ZKLINK = 0
    ZKEX = 1
