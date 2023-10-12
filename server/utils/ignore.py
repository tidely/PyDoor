""" Different Handlers for simplifying the CLI """

def keyboardinterrupt(func: object) -> object:
    """ Decorator to ignore KeyboardInterrupt """
    def wrapper(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except KeyboardInterrupt:
            print()

    return wrapper
