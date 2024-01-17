""" Different Handlers for simplifying the CLI """
from functools import wraps


def keyboardinterrupt(func: object) -> object:
    """ Decorator to ignore KeyboardInterrupt """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except KeyboardInterrupt:
            print()

    return wrapper
