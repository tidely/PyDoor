""" Clipboard functionality """
import logging

from modules.clients import Client


def copy(client: Client, text: str):
    """ Copy to client clipboard """
    logging.debug('Copying to client clipboard (%s)', client.port)
    client.write(b'COPY')
    client.write(text.encode())

    response = client.read().decode()
    if response != 'SUCCESS':
        logging.error('Error copying to client clipboard (%s): %s', client.port, response)
        raise RuntimeError(f'Error copying to client clipboard: {response}')

    logging.info('Copied "%s" to client clipboard (%s)', text, client.port)


def paste(client: Client) -> str:
    """ Paste from clipboard """
    logging.debug('Pasting from client clipboard (%s)', client.port)
    client.write(b'PASTE')

    response = client.read().decode()
    if response != 'SUCCESS':
        logging.error('Error pasting from clipboard (%s): %s', client.port, response)
        raise RuntimeError(f'Error pasting from clipboard: {response}')

    clipboard = client.read().decode()

    logging.info('Pasted "%s" from client clipboard (%s)', clipboard, client.port)
    return clipboard
