""" Custom Thread Class """
import threading
import queue
import uuid
from typing import Union


class Task(threading.Thread):
    """ Base Task Class """

    def __init__(self, *args, **kwargs):
        """ Create additional properties for task """

        self.identifer = str(uuid.uuid4())
        self.stop = threading.Event()
        self.output = queue.Queue()

        threading.Thread.__init__(self, *args, **kwargs)


def clean(tasks: list[Task]):
    """ Given a list of tasks, remove completed and processed ones """
    # Create a copy to prevent issues looping through
    tasks_copy = tasks.copy()
    for task in tasks_copy:
        if not task.is_alive() and (task.output is None or task.output.qsize() == 0):
            tasks.remove(task)
            continue


def find(tasks: list[Task], task_id: str) -> Union[Task, None]:
    """ Find a task with a specific task identifier, return None if not found """
    # Clean the task list
    clean(tasks)
    for task in tasks:
        if task_id != task.identifer:
            continue

        return task

    return None
