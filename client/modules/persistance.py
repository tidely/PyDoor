import os
import sys
import logging
import platform
from typing import Union

if platform.system() == 'Windows':
    from winreg import OpenKey, CloseKey, SetValueEx, DeleteValue
    from winreg import HKEY_CURRENT_USER, KEY_ALL_ACCESS, REG_SZ
    STARTUP_REG_NAME = 'PyDoor'


def add_startup() -> Union[str, None]:
    """ Add Client to startup """
    # returns None/error
    if platform.system() != 'Windows':
        return 'Startup feature is only for Windows'
    if getattr(sys, 'frozen', False):
        path = sys.executable
    elif __file__:
        path = os.path.abspath(__file__)
    try:
        key = OpenKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_ALL_ACCESS)
        SetValueEx(key, STARTUP_REG_NAME, 0, REG_SZ, path)
        CloseKey(key)
    except Exception as error:
        logging.error('Error adding client to startup: %s' % error)
        return error
    else:
        logging.info('Adding client to startup successful')


def remove_startup() -> Union[str, None]:
    """ Remove Client from Startup """
    # returns None/error
    if platform.system() != 'Windows':
        return 'Startup feature is only for Windows'
    try:
        key = OpenKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_ALL_ACCESS)
        DeleteValue(key, STARTUP_REG_NAME)
        CloseKey(key)
    except FileNotFoundError:
        # File was never registered.
        # Still returns True, since it's not in startup
        logging.info('FileNotFoundError: assume registry key does not exist')
    except WindowsError as error:
        logging.error('Error removing client from startup: %s' % error)
        return error
    else:
        logging.info('Removed Client from Startup')
