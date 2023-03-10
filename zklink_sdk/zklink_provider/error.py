class ZkLinkProviderError(Exception):
    pass


class AccountDoesNotExist(ZkLinkProviderError):
    def __init__(self, address, *args):
        self.address = address
        super().__init__(*args)


class AccountBalancesDoesNotExist(ZkLinkProviderError):
    def __init__(self, account_id, sub_account_id, *args):
        self.account_id = account_id
        self.sub_account_id = sub_account_id
        super().__init__(*args)
