"""Commands for networking"""

import time
import logging

from modules.clients import Client


def ping(client: Client) -> int:
    """Measure socket latency in ms"""
    logging.debug("Pinging client (%s)", client.port)

    ms_before = round(time.time() * 1000)
    client.write(b"PING")
    client.read()
    latency = round(time.time() * 1000) - ms_before

    logging.debug("Client (%s) latency is %sms", client.port, latency)
    return latency
