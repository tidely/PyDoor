""" Threaded Python Interpreter """
import logging
import queue
from contextlib import redirect_stdout
from io import StringIO

from utils.tasks import Task


def _pyshell(command: str, output_queue: queue.Queue) -> None:
    """ Run a python command, put output into a queue """
    logging.debug('Executing python command: %s', command)
    error_message = ''

    output = StringIO()
    with redirect_stdout(output):
        try:
            exec(command)
        except Exception as error:
            error_message = f'{error.__class__.__name__}: {str(error)}\n'

    # Write command output into queue
    output_queue.put(output.getvalue() + error_message)


def pyshell(command: str | list) -> Task:
    """ Run a python exec command inside of a thread """

    task = Task(
        target=_pyshell,
        args=[command],
        info=["Python", command],
        stop=None
    )

    task.start()
    return task
