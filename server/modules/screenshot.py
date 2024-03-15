""" Screenshot functionality """
import logging
from typing import Union
from datetime import datetime

from modules.clients import Client
from utils.timeout_handler import timeoutsetter


def screenshot(client: Client, timeout: Union[float, None] = 120.0) -> str:
    """ Take a screenshot and save it in a file, returns filename """
    logging.debug('Taking screenshot (%s)', client.port)
    client.write(b'SCREENSHOT')

    with timeoutsetter(client, timeout):
        img_data = client.read()

    if img_data.startswith(b'ERROR'):
        logging.error('Error taking screenshot (%s): %s', client.port, img_data.decode())
        raise RuntimeError(f'Error taking screenshot ({client.port}): {img_data.decode()}')

    filename = f'screenshot-{datetime.now()}.png'.replace(':', '-')
    with open(filename, 'wb') as file:
        file.write(img_data)
    logging.info('Saved screenshot at (%s): %s', client.port, filename)
    return filename
