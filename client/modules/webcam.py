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
            return arr.tobytes()
    raise RuntimeError('Could not capture webcam')
