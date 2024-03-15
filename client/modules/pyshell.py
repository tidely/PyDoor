"""Threaded Python Interpreter"""

import json
import logging
from io import StringIO
from contextlib import redirect_stdout, redirect_stderr
from typing import Union

from utils.tasks import Task


class ShellTask(Task):
    """Execute Python as task"""

    def __init__(self, command: str, *args, **kwargs) -> None:
        """Overwrite stop"""
        Task.__init__(self, *args, **kwargs)

        # Arguments
        self.command = command

        # Task cannot be stopped
        self.stop = None

        # Overwrite task name
        self.name = json.dumps(("Python", command))

    def run(self):
        """Execute python command"""
        logging.debug("Executing python command: %s", self.command)
        python_error = ""

        with redirect_stdout(StringIO()) as stdout, redirect_stderr(
            StringIO()
        ) as stderr:
            try:
                exec(self.command)
            except Exception as error:
                python_error = f"{error.__class__.__name__}: {str(error)}\n"

        # Write command output into queue
        self.output.put("".join((stdout.getvalue(), stderr.getvalue(), python_error)))


def pyshell(command: str) -> Task:
    """Run a python exec command inside of a thread"""

    task = ShellTask(command)
    task.start()
    return task
