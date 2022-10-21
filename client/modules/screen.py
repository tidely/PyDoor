import logging
from io import BytesIO
from typing import Union

import pyscreeze
from utils.errors import errors


def screenshot() -> Union[bool, bytes]:
    """ Take a screenshot """
    try:
        with BytesIO() as output:
            img = pyscreeze.screenshot()
            img.save(output, format='PNG')
            content = output.getvalue()
    except Exception as error:
        logging.error('Error taking screenshot: %s' % errors(error))
        return False, errors().encode()
    logging.info('Captured screenshot')
    return True, content
