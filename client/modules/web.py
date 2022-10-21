from typing import Union
import requests
import logging

from utils.errors import errors

def download(link: str, filename: str) -> Union[str, None]:
    """ Download files from the internet """
    try:
        request = requests.get(link)
        with open(filename) as file:
            file.write(request.content)
    except Exception as error:
        logging.error('Error downloading "%s" from %s: %s' % (filename, link, error))
        return errors(error)
    logging.info('Downloaded "%s" from %s' % (filename, link))
