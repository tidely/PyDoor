""" Timeout helper for clients """
from contextlib import contextmanager

from modules.clients import Client


@contextmanager
def timeoutsetter(client: Client, timeout: float) -> None:
    """ Temporarily set a clients timeout """
    default = client.conn.gettimeout()
    client.conn.settimeout(timeout)
    try:
        yield
    finally:
        client.conn.settimeout(default)
