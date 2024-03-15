""" Helper Decorators """
from typing import Callable

def run_till_true(func: Callable) -> object:
    """ Run a function until it returns true """
    def wrapper(*args, **kwargs):
        while True:
            if func(*args, **kwargs):
                break

    return wrapper
