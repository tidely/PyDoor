""" Timeout helper for clients """
from contextlib import contextmanager, suppress

from modules.clients import Client


@contextmanager
def timeoutsetter(client: Client, timeout: float | None) -> None:
    """ Temporarily set a clients timeout """
    default = client.conn.gettimeout()
    client.conn.settimeout(timeout)
    try:
        yield
    finally:
        # Ignore if client has disconnected
        with suppress(OSError, ConnectionError):
            client.conn.settimeout(default)
