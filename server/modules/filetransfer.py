import logging

from modules.clients import Client


def receive(client: Client, filename: str, save_name: str) -> None:
    """ Receive a file from the client """
    logging.debug('Receiving file "%s" from client (%s)' % (filename, client.id))
    client.write(b'SEND_FILE')
    client.write(filename.encode())

    with open(save_name, 'wb') as file:
        while True:
            data = client.read()
            if data == b'ERROR':
                logging.info('Client encountered error transferring file "%s" (%s)' % (filename, client.id))
                raise RuntimeError('Client encountered error transfering file: ' + client.read().decode())
            if data == b'FILE_TRANSFER_DONE':
                break
            file.write(data)

def send(client: Client, filename: str, save_name: str, blocksize: int = 32768) -> None:
    """ Send a file to client """
    logging.debug('Sending file "%s" to client (%s)' % (filename, client.id))

    client.write(b'RECEIVE_FILE')
    client.write(save_name.encode())
    if client.read().decode() == 'ERROR':
        raise RuntimeError('Error occurred sending file to client: ' + client.read().decode())

    try:
        with open(filename, 'rb') as file:
            while True:
                block = file.read(blocksize)
                if not block:
                    break
                client.write(block)

    except (FileNotFoundError, PermissionError) as error:
        logging.error('Unable to send file "%s" to client (%s): %s' % (filename, client.id, str(error)))
        client.write(b'FILE_TRANSFER_DONE')
    else:
        client.write(b'FILE_TRANSFER_DONE')
        logging.info('Successfully transferred file "%s" to client (%s)' % (filename, client.id))