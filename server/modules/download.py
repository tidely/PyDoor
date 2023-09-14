""" Download Functionality """
import json
import logging

from modules.clients import Client
from utils.timeout_handler import timeoutsetter


def download(client: Client, url: str, filename: str, timeout: int = 30) -> bool:
    """ Make the client download a file """
    logging.debug("Downloading file '%s' from '%s' to client (%s)", filename, url, client.id)

    client.write(b'DOWNLOAD')
    client.write(json.dumps((url, filename)).encode())

    with timeoutsetter(client, timeout):
        response = client.read().decode()

    if response != "Success":
        error = f"Error downloading file '{filename}' from '{url}' to client ({client.id}): {response}"
        logging.error(error)
        raise RuntimeError(error)

    logging.info("Downloaded file '%s' from '%s' to client (%s)", filename, url, client.id)
