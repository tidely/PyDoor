""" File transfer functionality """
import ssl
import logging

from modules.clients import Client


def receive(client: Client, filename: str, save_name: str) -> None:
    """ Receive a file from the client """
    logging.debug('Receiving file "%s" from client (%s)', filename, client.port)

    # Warn if socket isn't encrypted, since receive uses raw recv calls
    if not isinstance(client.conn, ssl.SSLSocket):
        logging.warning(
            "Non-ssl socket detected! Receive uses raw recv will which will not be encrypted!"
            )

    # File should be opened here to prevent request being sent, incase of an error
    with open(save_name, "wb") as file:

        client.write(b'SEND_FILE')
        client.write(filename.encode())

        # Check that file opens successfully
        response = client.read().decode()
        if response != 'FILE_OPENED':
            logging.error("Failed getting file from client: %s", response)
            raise RuntimeError(f"File Transfer failed: {response}")

        while True:
            data = client.conn.recv(4096)
            if data == b'FILE_TRANSFER_COMPLETE':
                # File transfer completed
                break
            file.write(data)

    logging.info(
        "File '%s' transferred from client '%s' successfully to '%s'",
        filename, client.port, save_name
    )


def send(client: Client, filename: str, save_name: str) -> None:
    """ Send a file to client """
    logging.debug('Sending file "%s" to client (%s)', filename, client.port)

    # Warn if socket isn't encrypted, since receive uses raw recv calls
    if not isinstance(client.conn, ssl.SSLSocket):
        logging.warning(
            "Non-ssl socket detected! Receive uses raw recv will which will not be encrypted!"
            )

    # File should be opened here to prevent request being sent, incase of an error
    with open(filename, "rb") as file:

        client.write(b'RECEIVE_FILE')
        client.write(save_name.encode())

        response = client.read().decode()
        if response != 'FILE_OPENED':
            raise RuntimeError(f'Client could not open file: {response}')

        client.conn.sendfile(file=file)

    # Indicate transfer has completed
    client.conn.sendall(b'FILE_TRANSFER_COMPLETE')
    logging.info('Successfully transferred file "%s" to client (%s)', filename, client.port)
