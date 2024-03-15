""" Shell functionality """
import logging
from typing import Union

from utils.timeout_handler import timeoutsetter
from modules.clients import Client


def shell(client: Client, command: str, timeout: Union[float, None] = 60.0) -> str:
    """ Run shell command on client """
    logging.debug("Sending shell command '%s' to client (%s)", command, client.port)

    client.write(b"SHELL")
    client.write(command.encode())

    with timeoutsetter(client, timeout):
        response = client.read().decode()

    logging.debug("Command (%s) output from client (%s): %s", command, client.port, response)
    return response


def python(client: Client, command: str, timeout: Union[float, None] = 60.0) -> str:
    """ Run python command on client """
    logging.debug("Sending python command '%s' to client (%s)", command, client.port)

    client.write(b"PYTHON")
    client.write(command.encode())

    with timeoutsetter(client, timeout):
        response = client.read().decode()

    logging.debug("Python command '%s' output from client (%s): %s", command, client.port, response)
    return response
