""" Clipboard functionality """
import pyperclip


def copy(data: str) -> None:
    """ Copy to clipboard """
    pyperclip.copy(data)


def paste() -> str:
    """ Paste from clipboard """
    return pyperclip.paste()
