"""Windows specific features"""

import ctypes


def lock():
    """Lock Machine"""
    ctypes.windll.user32.LockWorkStation()
