"""Helper Decorators"""

from functools import wraps
from typing import Callable


def run_till_true(func: Callable) -> Callable:
    """Run a function until it returns true"""

    @wraps(func)
    def wrapper(*args, **kwargs):
        while True:
            if func(*args, **kwargs):
                break

    return wrapper
