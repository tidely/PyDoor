""" Manage tasks on a client """
import json
import logging

from modules.clients import Client


def tasks(client: Client) -> list:
    """ Fetch running tasks on a client """
    logging.debug("Fetching tasks from client (%s)", client.port)

    client.write(b"TASKS")
    response = client.read().decode()

    logging.debug("Received tasks from client (%s): %s", client.port, response)
    return json.loads(response)


def stoptask(client: Client, task_id: str) -> bool:
    """ Stop a task on a client """
    logging.debug("Attempting to stop task (%s) on client (%s)", task_id, client.port)

    client.write(b"STOPTASK")
    client.write(task_id.encode())

    response = client.read().decode()
    if response != "STOPPED":
        logging.error("Task '%s' not stopped on client (%s): %s", task_id, client.port, response)
        raise RuntimeError(f'Task not stopped: {response}')

    logging.debug("Task '%s' stopped on client (%s)", task_id, client.port)


def output(client: Client, task_id: str) -> str:
    """ Attempt to get the output of a background task """
    logging.debug("Getting output for task (%s)", task_id)

    client.write(b'TASKOUTPUT')
    client.write(task_id.encode())

    response = client.read().decode()
    if response != 'READY':
        logging.error("No output from task (%s) on client (%s): %s", task_id, client.port, response)
        raise RuntimeError(f'No output from Task: {response}')

    logging.debug("Task (%s) returned output from client (%s)", task_id, client.port)
    return client.read().decode()


def find(task_list: list, task_id: str) -> str | None:
    """ Given a list of tasks, and a shortened task id, find full identifier """
    complete_id = None
    for task in task_list:
        if task[0].startswith(task_id):
            complete_id = task[0]
            break

    return complete_id
