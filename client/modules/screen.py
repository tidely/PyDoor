from io import BytesIO
import pyscreeze


def screenshot() -> bytes:
    """ Capture a screenshot """
    with BytesIO() as output:
        img = pyscreeze.screenshot()
        img.save(output, format='PNG')
        content = output.getvalue()

    return content
