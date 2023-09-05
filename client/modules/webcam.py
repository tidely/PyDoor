""" Webcam functionality """
from typing import Union

from cv2 import VideoCapture, imencode


def capture_webcam() -> Union[bytes, None]:
    """ Capture a webcam image """
    camera = VideoCapture(0)
    state, img = camera.read()
    camera.release()
    if state:
        is_success, arr = imencode('.png', img)
        if is_success:
            return arr.tobytes()
    raise RuntimeError('Could not capture webcam')
