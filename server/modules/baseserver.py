""" Base Server """
import logging
import ssl
import queue
import select
import socket
import threading
from contextlib import suppress

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

    def __init__(self, ssl_context: ssl.SSLContext) -> None:
        """ Create Thread and load certificate """
        # Create thread
        self.accept_thread = threading.Thread(target=self._accept, daemon=True)
        self.context = ssl_context

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

            try:
                ssl_sock = self.context.wrap_socket(conn, server_side=True)
            except ssl.SSLError as error:
                logging.error("Error during ssl wrapping: %s", str(error))
                continue


            client = Client(ssl_sock, address)

            # Get peer system information
            info = client.read().decode().strip().split()
            client.system, client.user, client.home, client.hostname = info

            self._clients.append(client)
            self.connections_queue.put(client)

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
