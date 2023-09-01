""" Windows specific features """
import ctypes


def lock() -> None:
    """ Lock Machine """
    ctypes.windll.user32.LockWorkStation()
