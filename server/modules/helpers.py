""" Use common commands without all the overhead """
import logging

from modules.clients import Client


def getcwd(client: Client) -> str:
    """ Get the current working directory """
    logging.info("Getting cwd from client (%s)", client.id)

    client.write(b"CWD")

    return client.read().decode()
