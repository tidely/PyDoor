"""
https://github.com/Y4hL/PyDoor

Author(s): Y4hL

License: [gpl-3.0](https://www.gnu.org/licenses/gpl-3.0.html)
"""
import logging
import platform
import socket
import threading
from queue import Queue

from utils.errors import errors
from utils.esocket import ESocket

from modules.clients import Client

if platform.system() != 'Windows':
    # readline allows movement with arrowkeys on linux
    try:
        import readline
    except ImportError:
        pass

logging.basicConfig(level=logging.CRITICAL)


class Server():
    """ Multi-connection Server class """

    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def __init__(self) -> None:
        self.thread = threading.Thread(target=self._accept)
        self.thread.daemon = True
        self.event = threading.Event()
        self.queue = Queue()
        self.clients = []

    def _accept(self) -> None:
        """ Accepts incoming connections """
        while not self.event.is_set():
            try:
                conn, address = self.sock.accept()
                conn.setblocking(True)

                esock = ESocket(conn, True)

                _, hostname = esock.recv()
                address += (hostname.decode(),)

                client = Client(esock, address)
                self.clients.append(client)
                self.queue.put(client)
            except Exception as error:
                logging.debug(errors(error))

    def start(self, address) -> None:
        """ Start the Server """

        self.sock.bind(address)
        self.sock.listen()
        self.address = address

        self.event.clear()

        self.thread.start()

    def stop(self) -> None:
        """ Stop the server """
        if not self.event.is_set():
            self.event.set()
        self.sock.shutdown(socket.SHUT_RDWR)

    def disconnect(self, client: Client) -> None:
        """ Disconnect client and remove from connection list """
        if client in self.clients:
            self.clients.remove(client)
        client.disconnect()

    def refresh(self, timeout: int = 1) -> None:
        """ Refreshes connections """
        clients = self.clients.copy()
        for client in clients:
            client.esock.sock.settimeout(timeout)
            try:
                client.send_json(['LIST'])
            except (BrokenPipeError, ConnectionResetError, BlockingIOError):
                self.disconnect(client)
            except TimeoutError:
                logging.info(f'{client.address} timed out')
                print(f'{client.address} timed out')
            else:
                client.esock.sock.settimeout(None)
