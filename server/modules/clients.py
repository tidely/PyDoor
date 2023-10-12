""" Client object """
import logging
import socket
import uuid

HEADER_LENGTH = 8


class Client:
    """ Client class """

    # List of tasks running on client
    tasklist = []

    # Client system information (collected during handshake)
    system: str = '' # platform.system()
    user: str = '' # getpass.getuser()
    home: str = '' # os.path.expanduser("~")
    hostname: str = '' # socket.gethostname()

    def __init__(self, conn: socket.socket, address: tuple) -> None:
        self.conn = conn
        self.address = address
        self.port = address[-1]
        self.identifier = uuid.uuid4()

    def fileno(self) -> int:
        """ Return file descriptior of client socket """
        return self.conn.fileno()

    def _read(self, amount: int) -> bytes:
        """ Receive raw data from peer """
        data = b''
        while len(data) < amount:
            buffer = self.conn.recv(amount)
            if not buffer:
                # Assume connection was closed
                logging.error('Assuming connection was closed: %s', str(self.address))
                raise ConnectionResetError
            data += buffer

        return data

    def read(self) -> bytes:
        """ Read messages from client """
        header = self._read(HEADER_LENGTH)
        message_length = int.from_bytes(header, 'big')
        return self._read(message_length)

    def write(self, data: bytes) -> None:
        """ Write message data to peer """
        # Create header for data
        header = len(data).to_bytes(HEADER_LENGTH, byteorder='big')
        message = header + data
        self.conn.sendall(message)
