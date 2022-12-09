import pyperclip


def copy(data: str) -> None:
    """ Copy to clipboard """
    try:
        pyperclip.copy(data)
    except pyperclip.PyperclipException as error:
        raise RuntimeError(str(error)) from error


def paste() -> str:
    """ Paste from clipboard """
    try:
        data = pyperclip.paste()
    except pyperclip.PyperclipException as error:
        raise RuntimeError(str(error)) from error

    return data
