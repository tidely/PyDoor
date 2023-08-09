import logging
import socket
from datetime import datetime

from modules.clients import Client

def screenshot(client: Client) -> str:
    """ Take a screenshot and save it in a file, returns filename """
    logging.debug('Taking screenshot (%s)' % client.id)
    client.write(b'SCREENSHOT')
    client.conn.settimeout(120)
    try:
        img_data = client.read()
    finally:
        client.conn.settimeout(socket.getdefaulttimeout())

    if img_data.startswith(b'ERROR'):
        logging.error('Error taking screenshot (%s): %s' % (client.id, img_data.decode()))
        raise RuntimeError('Error taking screenshot (%s): %s' % (client.id, img_data.decode()))

    filename = f'screenshot-{datetime.now()}.png'.replace(':', '-')
    with open(filename, 'wb') as file:
        file.write(img_data)
    logging.info('Saved screenshot at (%s): %s' % (client.id, filename))
    return filename
