""" Download functionality """
import threading

import requests


def _download(stream: requests.Response, filename: str) -> None:
    """ Download thread """
    with open(filename, "wb") as file:
        for chunk in stream.iter_content(chunk_size=16384):
            file.write(chunk)

def download(url: str, filename: str) -> None:
    """ Download file from url """

    # Request a download stream
    stream = requests.get(url, stream=True, allow_redirects=True, timeout=20)

    # Create a thread to download from stream
    thread = threading.Thread(target=_download, args=(stream, filename))
    thread.start()
