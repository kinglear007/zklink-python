from eth_account.messages import encode_structured_data
from eth_account.account import Account, SignedMessage

DOMAIN_NAME = 'ZkLink'
VERSION = 1


def getChangePubkeyMessage(
        pubKeyHash: str,
        nonce: int,
        accountId: int,
        verifyingContract: str,
        layerOneChainId: int
):
    domainType = [
        {"name": 'name', "type": 'string'},
        {"name": 'version', "type": 'string'},
        {"name": 'chainId', "type": 'uint256'},
        {"name": 'verifyingContract', "type": 'address'},
    ]
    ChangePubKey = [
        {"name": 'pubKeyHash', "type": 'bytes20'},
        {"name": 'nonce', "type": 'uint32'},
        {"name": 'accountId', "type": 'uint32'},
    ]
    domain = {
        "name": DOMAIN_NAME,
        "version": VERSION,
        "chainId": layerOneChainId,
        "verifyingContract": verifyingContract,
    }

    types = {
        "EIP712Domain": domainType,
        "ChangePubKey": ChangePubKey,
    }

    message = {
        "pubKeyHash": "0x" + pubKeyHash[:5],
        "nonce": nonce,
        "accountId": accountId,
    }
    data = {
        "types": types,
        "domain": domain,
        "primaryType": 'ChangePubKey',
        "message": message,
    }
    return data
