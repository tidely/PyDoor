""" Base Server """
import logging
import os
import queue
import select
import socket
import threading
import time
from contextlib import suppress

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from utils.timeout_handler import timeoutsetter
from modules.clients import Client


class Server:
    """
    Base Server
    """

    # Server address
    address = None

    # Create socket
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # List of clients
    _clients: list[Client] = []
    # Queue for new connections
    connections_queue = queue.Queue()
    # Event to stop listening to new connections
    accept_event = threading.Event()

    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        """ Create Thread and load certificate """
        # Create thread
        self.accept_thread = threading.Thread(target=self._accept, daemon=True)
        self.private_key = private_key

    def start(self, address: tuple) -> None:
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

            client = Client(conn, address)

            # Perform handshake with client
            try:
                self.handshake(client)
            except Exception as error:
                logging.debug('Handshake with peer failed: %s', str(error))
                conn.close()
            else:
                self._clients.append(client)
                self.connections_queue.put(client)

    def handshake(self, client: Client) -> None:
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

        # Sign public key using private key
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

        client.cipher = Cipher(
            algorithm=algorithms.AES256(derived_key),
            mode=modes.CBC(iv)
        )

        # Get peer system information
        info = client.read().decode().strip().split()
        client.system, client.user, client.home, client.hostname = info

        logging.info('Handshake completed with client (%s) at %s', client.port, client.address)

    def clients(self) -> list[Client]:
        """ List connected clients """
        if len(self._clients) == 0:
            return self._clients

        clients = self._clients.copy()

        # Check for disconnected clients
        readable, _, errors = select.select(clients, clients, clients, 60.0)

        # Type hints
        readable: list[Client]
        errors: list[Client]

        # Disconnect clients that returned an error
        for client in errors:
            self.disconnect(client)

        # Since there is data to read, server and client are out of sync
        # Try fixing this by removing the data in the buffer
        for client in readable:
            with timeoutsetter(client, 0.0):
                try:
                    data = client.read()
                except (OSError, ConnectionError):
                    # Peer has disconnected
                    self.disconnect(client)
                else:
                    logging.debug('Data in buffer (%s) during list: %s', client.port, data)

        return self._clients

    def ping(self, client: Client) -> int | bool:
        """ Measure socket latency in ms """
        logging.debug("Pinging client (%s)", client.port)

        ms_before = round(time.time() * 1000)
        client.write(b'PING')
        client.read()
        latency = round(time.time() * 1000) - ms_before

        logging.debug("Client (%s) latency is %sms", client.port, latency)
        return latency

    def disconnect(self, client: Client) -> None:
        """ Disconnect a specific client """
        logging.debug("Disconnecting client (%s)", client.port)
        client.conn.close()
        if client in self.clients():
            self._clients.remove(client)

    def shutdown(self) -> None:
        """ Shutdown server """
        logging.debug('Shutting down server')
        # Stop accept thread
        self.accept_event.set()

        # Suppress OSError (socket not connected)
        with suppress(OSError):
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
