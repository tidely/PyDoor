""" Base Server """
import logging
import ssl
import queue
import select
import socket
import threading
import selectors
from contextlib import suppress
from concurrent import futures

from utils.timeout_handler import timeoutsetter
from modules.clients import Client


class Server:
    """ Base Server class """

    # List of connected clients
    _clients: list[Client] = []
    # Event to stop listening for new connections
    _stop = threading.Event()

    def __init__(self,
            address: tuple[str, int],
            context: ssl.SSLContext | None = None,
            queue_new_connections: bool = True
        ) -> None:
        """ Create and wrap socket with SSL """
        # Create SSLSocket from context
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if isinstance(context, ssl.SSLContext):
            self.socket = context.wrap_socket(self.socket, server_side=True)
        else:
            logging.warning("No SSL Context provided! Running without SSL.")

        self.address = address
        self.new_connections = queue.Queue() if queue_new_connections else None

    def start(self) -> None:
        """ Start the server """
        self.socket.bind(self.address)
        self.socket.listen()
        self._stop.clear()
        threading.Thread(target=self.listen).start()

    def listen(self) -> None:
        """ Listen for incoming connections, and accept them using a threadpool """

        with futures.ThreadPoolExecutor() as executor, selectors.DefaultSelector() as selector:
            # Register socket to wait for incoming connections
            selector.register(self.socket, selectors.EVENT_READ)

            while not self._stop.is_set():
                for _ in selector.select(timeout=1):
                    executor.submit(self.accept)

    def accept(self) -> None:
        """ Accept incoming connection, gets called from self.accept """
        try:
            connection, address = self.socket.accept()
        except (BlockingIOError, TimeoutError):
            return

        client = Client(connection, address)
        # Receive system information
        info = client.read().decode().strip().split()
        client.system, client.user, client.home, client.hostname = info

        self._clients.append(client)

        if hasattr(self.new_connections, "put"):
            self.new_connections.put(client)

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

    def disconnect(self, client: Client) -> None:
        """ Disconnect a specific client """
        logging.debug("Disconnecting client (%s)", client.port)
        with suppress(OSError):
            client.conn.shutdown(socket.SHUT_RDWR)
        client.conn.close()
        if client in self._clients:
            self._clients.remove(client)

    def shutdown(self) -> None:
        """ Shutdown server """
        logging.debug('Shutting down server')
        # Stop accepting new clients
        self._stop.set()

        # Disconnect all clients
        for client in self._clients:
            self.disconnect(client)

        # Suppress OSError (socket not connected)
        with suppress(OSError):
            self.socket.shutdown(socket.SHUT_RDWR)
        self.socket.close()
