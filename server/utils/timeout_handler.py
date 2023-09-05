""" Timeout helper for clients """
from modules.clients import Client


class TimeoutSetter:
    """ Temporarily set a clients timeout """

    def __init__(self, client: Client, timeout: int,):
        """ Define variables, remember client timeout """
        self.sock = client.conn
        self.default = client.conn.gettimeout()
        self.timeout = timeout

    def __enter__(self) -> None:
        """ Set the socket timeout """
        self.sock.settimeout(self.timeout)

    def __exit__(self, exc_type, exc_value, exc_tb) -> None:
        """ Reset socket timeout """
        self.sock.settimeout(self.default)
