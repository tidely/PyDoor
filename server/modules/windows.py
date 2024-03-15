"""Windows specific features"""

import logging

from modules.clients import Client


def lock_machine(client: Client):
    """Lock a client machine"""
    logging.debug("Attempting to lock client machine (%s)", client.port)
    client.write(b"LOCK")

    response = client.read().decode()
    if response != "LOCKED":
        logging.error("Unable to lock client (%s): %s", client.port, response)
        raise RuntimeError(f"Unable to lock client ({client.port}): {response}")
