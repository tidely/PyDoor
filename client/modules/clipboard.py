import logging
from typing import Union

import pyperclip
from utils.errors import errors


def copy(text: str) -> Union[None, str]:
    """
    Copy text into clipboard

    returns error/None
    """
    try:
        pyperclip.copy(text)
    except pyperclip.PyperclipException as error:
        logging.error('Error copying "%s" to clipboard: %s' % (text, errors(error)))
        return errors(error)
    else:
        logging.info('Copied "%s" to clipboard' % text)

def paste() -> Union[bool, str]:
    """
    Pastes clipboard 

    returns True/False, clipboard/error
    """
    try:
        clipboard = pyperclip.paste()
    except pyperclip.PyperclipException as error:
        logging.error('Could not paste from clipboard: %s' % errors(error))
        return False, errors(error)
    logging.info('Pasted from clipboard: %s' % clipboard)
    return True, clipboard
