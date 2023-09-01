import os
import platform


def clear() -> None:
    """ Clear the terminal on different OS's """
    os.system('cls' if platform.system() == 'Windows' else 'clear')

