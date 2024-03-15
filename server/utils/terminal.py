""" Terminal functionality """
import os
import platform
from typing import Callable, Optional
from functools import wraps
from contextlib import suppress

from colorama import Fore

from modules.clients import Client
from modules.tasks import Task


def require_client(func: Callable) -> Callable:
    """ Decorator to require server.client to be defined to run function """
    @wraps(func)
    def wrapper(*args, **kwargs):
        client: Optional[Client] = args[0].client
        if client is None:
            print("Select a client first.")
        else:
            func(*args, **kwargs)

    return wrapper


def ignore(*exceptions) -> Callable:
    """ Create decorator to ignore exceptions """
    def decorator(function: Callable) -> Callable:
        """ Create wrapper """
        @wraps(function)
        def wrapper(*args, **kwargs):
            """ Wrapper to ignote  """
            with suppress(*exceptions):
                function(*args, **kwargs)
            print()
        return wrapper
    return decorator


def clear():
    """ Clear the terminal on different OS's """
    os.system('cls' if platform.system() == 'Windows' else 'clear')


def increase_timeout_prompt() -> bool:
    """ Prompt user to increase timeout limit """
    print('Client did not respond in time.')
    choice = input('Do you want to remove the timeout? ')
    return choice.strip().lower().startswith('y')


def task_print(tasks: list[Task]):
    """ Given a list of tasks, print them nicely to the user """
    if len(tasks) == 0:
        print("No tasks are running.")
        return

    print("-Tasks-")
    print(f"State: {Fore.GREEN}Running{Fore.WHITE} - {Fore.RED}Stopped with output{Fore.WHITE}\n")
    for task in tasks:

        # Always print identifier
        print(f"ID: {task.identifier[:5]} | ", end='')

        # Print command type and status
        status = f"{Fore.GREEN if task.native_id else Fore.RED}{task.command}{Fore.WHITE}"
        print(f"Type: {status} | ", end='')

        # Additional paremeters by task type
        match task.command:
            case "Download":
                print(f"url: {task.extra[0]} | file: {task.extra[1]}")
            case "Python":
                print(f"Command: {task.extra[0]}")


def make_prompt(client: Client, cwd: str) -> str:
    """ Given a client and a cwd, generate the proper shell prompt for it """

    match client.system:
        case "Windows":
            prompt = f"{cwd}> "
        case "Linux":
            prompt = f"{client.user}@{client.hostname}:{cwd.replace(client.home, '~')}$ "
        case "Darwin":
            if cwd == client.home:
                folder = '~'
            elif os.path.split(cwd)[0] == "/":
                # If cwd is root or one subfolder down
                folder = cwd
            else:
                # Only display current folder
                folder = os.path.basename(cwd)

            prompt = f"{client.user}@{client.hostname} {folder} % "

        case _:
            # Use Windows style by default
            prompt = f"{cwd}> "

    return prompt
