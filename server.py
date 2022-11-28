import os
import socket
import queue
import threading
import platform
import logging
import select
import uuid

from cryptography import x509
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


logging.basicConfig(level=logging.DEBUG)

# Padding for AES
pad = padding.PKCS7(256)
header_length = 8

menu_help = """
Commands:

list
open (ID)
shutdown
help
"""

interact_help = """
Available commands:

shell
python
exit/back
"""

class Client:
    """ Client class """

    def __init__(self, conn: socket.socket, address: tuple, id: str) -> None:
        self.conn = conn
        self.address = address
        self.id = id

    def add_cipher(self, cipher: Cipher) -> None:
        """ Add a cipher """
        self.cipher = cipher

    def _encrypt(self, data: bytes) -> bytes:
        """ Encrypt data """

        # Pad data
        padder = pad.padder()
        padded_data = padder.update(data) + padder.finalize()

        # Encrypt padded data
        encryptor = self.cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        return encrypted_data

    def _decrypt(self, data: bytes) -> bytes:
        """ Decrypt data """

        # Decrypt data
        decryptor = self.cipher.decryptor()
        decrypted_data = decryptor.update(data) + decryptor.finalize()

        # Unpad data
        unpadder = pad.unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        return unpadded_data

    def __read(self, amount: int, blocking: bool = False) -> bytes:
        """ Receive raw data from peer """
        while True:
            # Check if socket is readable
            readable, _, errors = select.select([self.conn], [self.conn], [self.conn])
            if errors:
                raise OSError('Could not read from socket: %s' % str(self.address))
            if readable:
                # Read of socket
                data = self.conn.recv(amount)
                if data:
                    return data
                else:
                    # Assume socket is closed
                    logging.debug('Assuming socket is closed')
                    raise ConnectionResetError
            # Only run the loop once if blocking is set to False
            if not blocking:
                break

        raise TimeoutError('Could not read from socket: %s' % str(self.address))

    def _read(self, blocking: bool = False) -> bytes:
        """ Read messages from client """
        header = self.__read(header_length, blocking=blocking)
        message_length = int.from_bytes(header, 'big')
        return self.__read(message_length, blocking=blocking)

    def _write(self, data: bytes, blocking: bool = False) -> None:
        """ Write message data to peer """
        # Create header for data
        header = len(data).to_bytes(header_length, byteorder='big')
        message = header + data
        while True:
            # Check if socket is readable
            _, writeable, errors = select.select([self.conn], [self.conn], [self.conn])
            if errors:
                break
            if writeable:
                # Write to socket
                self.conn.sendall(message)
                return

            # Only run the loop once if blocking is set to False
            if not blocking:
                break

        raise OSError('Could not write to socket: %s' % str(self.address))

    def read(self, blocking: bool = False) -> bytes:
        """ Read encrypted messages from peer """
        return self._decrypt(self._read(blocking=blocking))

    def write(self, data: bytes, blocking: bool = False) -> bool:
        """ Encrypt a message and send it to a peer """
        return self._write(self._encrypt(data), blocking=blocking)

class BaseServer:
    """
    Base Server
    """

    # Define header length
    header_length = 8

    # Server address
    address = None

    # Create socket
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(False)

    # List of clients
    clients = []
    # List of client ids
    ids = []
    # Queue for new connections
    connections_queue = queue.Queue()
    # Event to stop listening to new connections
    accept_event = threading.Event()

    def __init__(self,
        certificate: x509.Certificate,
        private_key: ec.EllipticCurvePrivateKey
        ) -> None:
        """ Create Thread and load certificate """
        # Create thread
        self.accept_thread = threading.Thread(target=self._accept, daemon=True)

        self.certificate = certificate
        self.private_key = private_key

    def start(self, address) -> None:
        """ Start the server """
        self.sock.bind(address)
        self.sock.listen()
        self.address = address

        self.accept_event.clear()

        self.accept_thread.start()

    def _accept(self) -> None:
        """ Accept incoming connections """
        while not self.accept_event.is_set():
            try:
                conn, address = self.sock.accept()
            except BlockingIOError:
                continue
            id = str(uuid.uuid4())[:5]
            while id in self.ids:
                id = uuid.uuid4[:5]
            client = Client(conn, address, id)
            try:
                cipher = self.handshake(client)
            except Exception as error:
                logging.debug('Handshake with peer failed: %s' % str(error))
                conn.close()
            else:
                client.add_cipher(cipher)
                self.clients.append(client)
                self.connections_queue.put(client)

    def handshake(self, client: Client, _blocking: bool = True) -> Cipher:
        """
        Handshake 

        Generate keypair
        Exchange public keys
        Verify signature
        Generate shared session key
        Server sends IV for AES256
        Create AES cipher
        """

        # Keys used for session
        private_key = ec.generate_private_key(ec.SECP521R1())
        pem_public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Sign public key using certificate private key
        signature = self.private_key.sign(
            pem_public_key,
            ec.ECDSA(hashes.SHA512())
        )
        client._write(pem_public_key, blocking=_blocking)
        serialized_peer_public_key = client._read(blocking=_blocking)
        client._write(signature, blocking=_blocking)

        # Exchange private and peer public key for shared key
        peer_public_key = serialization.load_pem_public_key(serialized_peer_public_key)
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

        # Derive key
        derived_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=None,
            info=None
        ).derive(shared_key)

        # Share IV for AES
        iv = os.urandom(16)
        client._write(iv, blocking=_blocking)

        cipher = Cipher(
            algorithm=algorithms.AES256(derived_key),
            mode=modes.CBC(iv)
        )
        logging.info('Handshake completed successfully')
        return cipher

    def list(self) -> list:
        """ List connected clients """
        clients = self.clients.copy()

        # Check for disconnected clients
        sockets = [client.conn for client in clients]
        readable, _, errors = select.select(sockets, sockets, sockets)

        for client in clients:
            # Check for errors
            if client.conn in errors:
                self.clients.remove(client)
            if client.conn in readable:
                # Check if socket is still connected
                try:
                    data = client._read()
                except OSError:
                    # Peer has disconnected
                    self.clients.remove(client)
                else:
                    # Buffer had data
                    logging.debug('Received data from %s during listing: %s' % (client.address, data))

        return self.clients

    def shutdown(self) -> None:
        """ Shutdown server """
        logging.debug('Shutting down server')
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
        except Exception as error:
            logging.error('An error occurred while server was shutting down: %s' % str(error))

class Server(BaseServer):
    """ Server for interacting with Client API """

    def __init__(self, certificate: x509.Certificate, private_key: ec.EllipticCurvePrivateKey):
        super().__init__(certificate, private_key)

    def shell(self, client: Client, command: str) -> None:
        """ Execute a shell command on client """
        client.write(b'SHELL')
        client.write(command.encode())
        return client.read(blocking=True)


class ServerCLI(Server):
    """ CLI for BaseServer """

    def __init__(self, certificate: x509.Certificate, private_key: ec.EllipticCurvePrivateKey):
        super().__init__(certificate, private_key)

    def cli(self) -> None:
        """ Start CLI """
        while True:
            try:
                self.menu()
            except KeyboardInterrupt:
                print('Ctrl-C detected: Shutting down server')
                self.shutdown()
                break
            except Exception as error:
                logging.critical('Critical errors occurred: %s' % str(error))

    def menu(self) -> None:
        """ Menu for interacting with clients """
        while True:
            command, *args = input('> ').split()

            match command:
                case 'help':
                    print(menu_help)
                case 'open':
                    try:
                        self.select(args)
                    except KeyboardInterrupt:
                        # Quit selector when ctrl-c is detected
                        print()
                        continue
                    except Exception as error:
                        logging.error('Client experiened an error: %s' % str(error))
                        continue
                case 'list':
                    self.list_cli()
                case 'shutdown':
                    raise KeyboardInterrupt

    def select(self, *args) -> None:
        """ Interact with a client """
        selected_client = None
        argument = args[0]
        if not argument:
            print('No client ID was given')
            return
        clients = self.clients.copy()
        for client in clients:
            if client.id == argument[0]:
                selected_client = client
        if selected_client is None:
            print('Invalid client ID')
            return

        while True:
            if self.interact(client):
                break

    def interact(self, client: Client) -> None:
        """ Interact with a client """
        command, *args = input(f'{client.address[0]}> ').split()
        match command:
            case 'help':
                print(interact_help)
            case 'exit' | 'back':
                return True
            case 'shell':
                self.shell_cli(client)
            case 'python':
                self.python_cli()

    def list_cli(self):
        """ CLI for list """
        clients = self.list()
        for client in clients:
            print(f'ID: {client.id} / Address: {client.address}')

    def shell_cli(self, client: Client) -> None:
        """ Open a shell to client """
        logging.debug('Launched shell')
        while True:
            command = input('shell> ')
            if command.strip() == 'exit':
                break
            elif command.strip() in ['clear', 'cls']:
                if platform.system() == 'Windows':
                    os.system('cls')
                else:
                    os.system('clear')
                continue

            print(self.shell(client, command))

    def python_cli(self) -> None:
        """ Open a python interpreter to client """
        logging.debug('Launched python interpreter')


if __name__ == '__main__':

    with open('cert.pem', 'rb') as file:
        cert = x509.load_pem_x509_certificate(file.read())

    with open('key.pem', 'rb') as file:
        private_key = serialization.load_pem_private_key(file.read(), None)

    server = ServerCLI(cert, private_key)
    server.start(('localhost', 6969))
    client = server.connections_queue.get()
    client.write(b'hello world')
    server.cli()
