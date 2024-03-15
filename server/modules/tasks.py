""" Manage tasks on a client """
import json
import logging
from typing import NamedTuple, Union

from modules.clients import Client


class Task(NamedTuple):
    """ Task object """
    identifier: str
    native_id: Union[int, None]
    command: str
    extra: list


def create_task(arguments: list) -> Task:
    """ Handle the extra paremeters when passing into a Task """
    identifier, native_id, command, *extra = arguments
    return Task(identifier, native_id, command, extra)


def tasks(client: Client) -> list[Task]:
    """ Fetch running tasks on a client """
    logging.debug("Fetching tasks from client (%s)", client.port)

    client.write(b"TASKS")
    response = client.read().decode()

    logging.debug("Received tasks from client (%s): %s", client.port, response)
    return list(map(create_task, json.loads(response)))


def stoptask(client: Client, task: Task):
    """ Stop a task on a client """
    logging.debug("Attempting to stop task (%s) on client (%s)", task.identifier, client.port)

    client.write(b"STOPTASK")
    client.write(task.identifier.encode())

    response = client.read().decode()
    if response != "STOPPED":
        logging.error(
            "Task '%s' not stopped on client (%s): %s",
            task.identifier, client.port, response
        )
        raise RuntimeError(f'Task not stopped: {response}')

    logging.debug("Task '%s' stopped on client (%s)", task.identifier, client.port)


def output(client: Client, task: Task) -> str:
    """ Attempt to get the output of a background task """
    logging.debug("Getting output for task (%s)", task.identifier)

    client.write(b'TASKOUTPUT')
    client.write(task.identifier.encode())

    response = client.read().decode()
    if response != 'READY':
        logging.error(
            "No output from task (%s) on client (%s): %s",
            task.identifier, client.port, response
        )
        raise RuntimeError(f'No output from Task: {response}')

    logging.debug("Task (%s) returned output from client (%s)", task.identifier, client.port)
    return client.read().decode()


def find(task_list: list[Task], task_id: str) -> Union[Task, None]:
    """ Find task from a list given a shortened task identifier, None if not found """
    return next((task for task in task_list if task.identifier.startswith(task_id)), None)
