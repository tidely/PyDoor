import logging
from typing import Union

import cv2


def capture_webcam() -> Union[bytes, None]:
    """ Capture a webcam image """
    camera = cv2.VideoCapture(0)
    state, img = camera.read()
    camera.release()
    if state:
        is_success, arr = cv2.imencode('.png', img)
        if is_success:
            logging.info('Captured webcam')
            return arr.tobytes()
    logging.error('Error capturing webcam')
