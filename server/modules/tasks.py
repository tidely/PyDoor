""" Manage tasks on a client """
import json
import logging

from modules.clients import Client


def tasks(client: Client) -> list:
    """ Fetch running tasks on a client """
    logging.debug("Fetching tasks from client (%s)", client.id)

    client.write(b"TASKS")
    response = client.read().decode()

    logging.info("Received tasks from client (%s): %s", client.id, response)
    return json.loads(response)


def stoptask(client: Client, task_id: str) -> bool:
    """ Stop a task on a client """
    logging.debug("Attempting to stop task (%s) on client (%s)", task_id, client.id)

    client.write(b"STOPTASK")
    client.write(task_id.encode())

    response = client.read().decode()
    if response != "STOPPED":
        return False

    return True
