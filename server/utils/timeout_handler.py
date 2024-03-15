""" Timeout helper for clients """
from contextlib import contextmanager, suppress
from typing import Generator, Any, Union

from modules.clients import Client


@contextmanager
def timeoutsetter(client: Client, timeout: Union[float, None]) -> Generator[None, Any, Any]:
    """ Temporarily set a clients timeout """
    default = client.conn.gettimeout()
    client.conn.settimeout(timeout)
    try:
        yield
    finally:
        # Ignore if client has disconnected
        with suppress(OSError, ConnectionError):
            client.conn.settimeout(default)
