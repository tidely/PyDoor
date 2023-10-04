""" Threaded download functionality """
import threading

import requests

from utils.tasks import Task


def download_stream(stream: requests.Response, filename: str, stop_event: threading.Event) -> None:
    """ Download a file from a stream """
    with open(filename, "wb") as file:
        for chunk in stream.iter_content(chunk_size=16384):
            file.write(chunk)
            if stop_event.is_set():
                return


def download(url: str, filename: str) -> Task:
    """ Download file from url """

    # Request a download stream
    stream = requests.get(url, stream=True, allow_redirects=True, timeout=20)

    task = Task(
        target=download_stream,
        args=[stream, filename],
        info=("Download", url, filename),
        output=None
    )

    task.start()
    return task
