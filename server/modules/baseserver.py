import os
import socket
import queue
import threading
import logging
import select
import uuid

from cryptography import x509
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from modules.clients import Client


class BaseServer:
    """
    Base Server
    """

    # Server address
    address = None

    # Create socket
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

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
            except (BlockingIOError, TimeoutError):
                continue

            # Generate a new unique id for client
            id = str(uuid.uuid4())[:5]
            while id in self.ids:
                id = uuid.uuid4[:5]

            client = Client(conn, address, id)

            # Perform handshake with client
            try:
                cipher = self.handshake(client)
            except Exception as error:
                logging.debug('Handshake with peer failed: %s' % str(error))
                conn.close()
            else:
                client.add_cipher(cipher)
                self.clients.append(client)
                self.connections_queue.put(client)

    def handshake(self, client: Client) -> Cipher:
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
        # Exchange public keys
        client._write(pem_public_key)
        serialized_peer_public_key = client._read()
        client._write(signature)

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
        client._write(iv)

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
                client.conn.settimeout(0)
                try:
                    data = client._read()
                except OSError:
                    # Peer has disconnected
                    self.clients.remove(client)
                else:
                    # Buffer had data
                    logging.debug('Received data from %s during listing: %s' % (client.address, data))
                finally:
                    client.conn.settimeout(socket.getdefaulttimeout())

        return self.clients

    def shutdown(self) -> None:
        """ Shutdown server """
        logging.debug('Shutting down server')
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
        except OSError:
            # Socket was not connected.
            pass
        except Exception as error:
            logging.error('An error occurred while server was shutting down: %s' % str(error))

