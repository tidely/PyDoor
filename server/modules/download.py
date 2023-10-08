""" Download Functionality """
import json
import logging

from modules.clients import Client
from utils.timeout_handler import timeoutsetter


def download(client: Client, url: str, filename: str, timeout: float | None = 30.0) -> bool:
    """ Make the client download a file """
    logging.debug("Downloading file '%s' from '%s' to client (%s)", filename, url, client.port)

    client.write(b'DOWNLOAD')
    client.write(json.dumps((url, filename)).encode())

    # Waits for the client to start the download, not for it to finish
    with timeoutsetter(client, timeout):
        response = client.read().decode()

    if response != "Success":
        error = f"Error downloading file '{filename}' " \
            f"from '{url}' to client ({client.port}): {response}"
        logging.error(error)
        raise RuntimeError(error)

    logging.info("Downloaded file '%s' from '%s' to client (%s)", filename, url, client.port)
