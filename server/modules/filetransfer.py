""" File transfer functionality """
import os
import logging

from modules.clients import Client


def receive(client: Client, filename: str, save_name: str) -> None:
    """ Receive a file from the client """
    logging.debug('Receiving file "%s" from client (%s)', filename, client.id)

    client.write(b'SEND_FILE')
    client.write(filename.encode())

    with open(save_name, 'wb') as file:
        while True:
            data = client.read()
            if data == b'ERROR':
                error = client.read().decode()
                logging.info('File "%s" transfer failed (%s): %s', filename, client.id, error)
                raise RuntimeError(f'File transfer failed: {error}')
            if data == b'FILE_TRANSFER_DONE':
                break
            file.write(data)


def send(client: Client, filename: str, save_name: str, blocksize: int = 32768) -> None:
    """ Send a file to client """
    logging.debug('Sending file "%s" to client (%s)', filename, client.id)

    # Check that the file exists and it's permissions before calling client
    if not os.path.isfile(filename):
        raise FileNotFoundError

    if not os.access(filename, os.R_OK):
        raise PermissionError

    client.write(b'RECEIVE_FILE')
    client.write(save_name.encode())

    response = client.read().decode()
    if response != 'FILE_OPENED':
        raise RuntimeError(f'Client could not open file: {response}')

    with open(filename, 'rb') as file:
        while True:
            block = file.read(blocksize)
            if not block:
                break
            client.write(block)

    logging.info('Successfully transferred file "%s" to client (%s)', filename, client.id)
    client.write(b'FILE_TRANSFER_DONE')
