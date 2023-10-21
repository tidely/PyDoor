""" Custom Thread Class """
import threading
import queue
import json
import uuid


class Task(threading.Thread):
    """ Default Task Class """

    def __init__(self,
            target: object,
            args: list,
            info: list,
            stop: threading.Event | None = threading.Event(),
            output: queue.Queue | None = queue.Queue(),
            daemon: bool = False
        ) -> None:
        """ Initialize thread """

        # Unique task identifier
        self.identifer = str(uuid.uuid4())

        # Append additional options to args
        if stop:
            args.append(stop)
        if output:
            args.append(output)

        threading.Thread.__init__(self,
            target=target,
            args=args,
            daemon=daemon
        )
        self.name = json.dumps(info)
        self.stop = stop
        self.output = output


def clean(tasks: list[Task]) -> None:
    """ Given a list of tasks, remove completed and processed ones """
    # Create a copy to prevent issues looping through
    tasks_copy = tasks.copy()
    for task in tasks_copy:
        if not task.is_alive() and (task.output is None or task.output.qsize() == 0):
            tasks.remove(task)
            continue


def find(tasks: list[Task], task_id: str) -> Task | None:
    """ Find a task with a specific task identifier, return None if not found """
    # Clean the task list
    clean(tasks)
    for task in tasks:
        if task_id != task.identifer:
            continue

        return task

    return None
