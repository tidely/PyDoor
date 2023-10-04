""" Manage tasks on a client """
import json
import logging

from modules.clients import Client


def tasks(client: Client) -> list:
    """ Fetch running tasks on a client """
    logging.debug("Fetching tasks from client (%s)", client.id)

    client.write(b"TASKS")
    response = client.read().decode()

    logging.debug("Received tasks from client (%s): %s", client.id, response)
    return json.loads(response)


def stoptask(client: Client, task_id: str) -> bool:
    """ Stop a task on a client """
    logging.debug("Attempting to stop task (%s) on client (%s)", task_id, client.id)

    client.write(b"STOPTASK")
    client.write(task_id.encode())

    response = client.read().decode()
    if response != "STOPPED":
        logging.error("Task '%s' does not exist on client (%s)", task_id, client.id)
        raise RuntimeError(f'Task not stopped: {response}')

    logging.debug("Task '%s' stopped on client (%s)", task_id, client.id)


def output(client: Client, task_id: str) -> str:
    """ Attempt to get the output of a background task """
    logging.debug("Getting output for task (%s)", task_id)

    client.write(b'TASKOUTPUT')
    client.write(task_id.encode())

    response = client.read().decode()
    if response != 'READY':
        logging.error("Task (%s) did not return output from client (%s): %s", task_id, client.id, response)
        raise RuntimeError(f'No output from Task: {response}')

    logging.debug("Task (%s) returned output from client (%s)", task_id, client.id)
    return client.read().decode()


def find(task_list: list, task_id: str) -> str:
    """ Given a list of tasks, and a shortened task id, find full identifier """
    complete_id = None
    for task in task_list:
        if task[0].startswith(task_id):
            complete_id = task[0]
            break

    return complete_id
