import importlib.resources as pkg_resources
import json

from . import contract_abi

zklink_abi_cache = None
ierc20_abi_cache = None

__all__ = ['zklink_abi', 'erc20_abi']


def zklink_abi():
    global zklink_abi_cache

    if zklink_abi_cache is None:
        abi_text = pkg_resources.read_text(contract_abi, 'ZkLink.json')
        zklink_abi_cache = json.loads(abi_text)['abi']

    return zklink_abi_cache


def erc20_abi():
    global ierc20_abi_cache

    if ierc20_abi_cache is None:
        abi_text = pkg_resources.read_text(contract_abi, 'IERC20.json')
        ierc20_abi_cache = json.loads(abi_text)['abi']

    return ierc20_abi_cache
