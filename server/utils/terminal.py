import os
import platform


def clear() -> None:
    """ Clear the terminal on different OS's """
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")
