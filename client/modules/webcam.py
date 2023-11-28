""" Webcam functionality """
from cv2 import VideoCapture, imencode


def capture_webcam() -> bytes:
    """ Capture a webcam image """
    camera = VideoCapture(0)
    state, img = camera.read()
    camera.release()
    if not state:
        raise RuntimeError('Could not open camera (no permissions, or disconnected)')

    success, png = imencode('.png', img)
    if not success:
        raise RuntimeError('Could not convert capture to png.')

    return png.tobytes()
