""" Terminal functionality """
import os
import platform
from colorama import Fore


def clear() -> None:
    """ Clear the terminal on different OS's """
    os.system('cls' if platform.system() == 'Windows' else 'clear')


def increase_timeout_prompt() -> bool:
    """ Prompt user to increase timeout limit """
    print('Client did not respond in time.')
    choice = input('Do you want to remove the timeout? ')
    return choice.strip().lower().startswith('y')


def task_print(tasks: list) -> None:
    """ Given a list of tasks, print them nicely to the user """
    if len(tasks) == 0:
        print("No tasks are running.")
        return

    print("-Tasks-")
    print(f"State: {Fore.GREEN}Running{Fore.WHITE} - {Fore.RED}Stopped with output{Fore.WHITE}\n")
    for task in tasks:
        identifier, native_id, command, *params = task

        # Always print identifier
        print(f"ID: {identifier[:5]} | ", end='')

        # Print command type and status
        print(f"Type: {Fore.GREEN if native_id else Fore.RED}{command}{Fore.WHITE} | ", end='')

        # Additionals paremeters by type
        match command:
            case "Download":
                print(f"url: {params[0]} | file: {task[1]}")
            case "Python":
                print(f"Command: {params[0]}")
