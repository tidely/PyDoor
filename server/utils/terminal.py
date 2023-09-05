""" Terminal functionality """
import os
import platform


def clear() -> None:
    """ Clear the terminal on different OS's """
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def increase_timeout_prompt():
    """ Prompt user to increase timeout limit """
    print('Client did not respond in time.')
    choice = input('Do you want to remove the timeout? ')
    if choice.strip().lower().startswith('y'):
        return True

    return False

def task_print(tasks: list) -> None:
    """ Given a list of tasks, print them nicely to the user """
    if len(tasks) == 0:
        print("No tasks are running.")
        return

    print("Running Tasks\n")
    for task in tasks:
        match task[0]:
            case "download":
                print(f"Type: Download | url: {task[1]} | file: {task[2]} | ThreadID: {task[3]}")
