import logging

from modules.clients import Client


def copy(client: Client, text: str) -> None:
    """ Copy to client clipboard """
    logging.debug('Copying to client clipboard (%s)' % client.id)
    client.write(b'COPY')
    client.write(text.encode())
    if client.read() == b'ERROR':
        error = client.read().decode()
        logging.error('Error copying to client clipboard (%s): %s' % (client.id, error))
        raise RuntimeError(f'Error copying to client clipboard: {error}')

    logging.info('Copied "%s" to client clipboard (%s)' % (text, client.id))

def paste(client: Client) -> str:
    """ Paste from clipboard """
    logging.debug('Pasting from client clipboard')
    client.write(b'PASTE')
    clipboard = client.read().decode()
    if clipboard == 'ERROR':
        error = client.read().decode()
        logging.error('Error pasting from clipboard (%s): %s' % (client.id, error))
        raise RuntimeError(f'Error pasting from clipboard: {error}')

    logging.info('Pasted "%s" from client clipboard (%s)' % (clipboard, client.id))
    return clipboard