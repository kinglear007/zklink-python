class ZkLinkProviderError(Exception):
    pass


class AccountDoesNotExist(ZkLinkProviderError):
    def __init__(self, address, *args):
        self.address = address
        super().__init__(*args)
