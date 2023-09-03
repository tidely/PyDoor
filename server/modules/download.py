""" Download Functionality """
import json
import logging

from modules.clients import Client


def download(client: Client, url: str, filename: str) -> bool:
    """ Make the client download a file """
    logging.debug("Downloading file '%s' from '%s' to client (%s)", filename, url, client.id)

    client.write(b'DOWNLOAD')
    client.write(json.dumps((url, filename)).encode())

    response = client.read().decode()

    if response != "Success":
        logging.error("Error downloading file '%s' from '%s' to client (%s): %s", filename, url, client.id, response)
        raise RuntimeError(f"Error downloading file '{filename}' from '{url}' to client ({client.id}): {response}")

    logging.info("Downloaded file '%s' from '%s' to client (%s)", filename, url, client.id)
