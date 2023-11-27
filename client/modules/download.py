""" Threaded download functionality """
import json

import requests

from utils.tasks import Task


class DownloadTask(Task):
    """ Download Task """

    def __init__(self, stream: requests.Response, filename: str, *args, **kwargs) -> None:
        """ Overwrite output """
        Task.__init__(self, *args, **kwargs)

        # Arguments
        self.stream = stream
        self.filename = filename

        # Task has no output
        self.output = None

        # Overwrite task name
        self.name = json.dumps(("Download", stream.url, filename))

    def run(self) -> None:
        """ Download from stream """
        with open(self.filename, "wb") as file:
            for chunk in self.stream.iter_content(chunk_size=16384):
                file.write(chunk)
                if self.stop.is_set():
                    break


def download(url: str, filename: str) -> Task:
    """ Download file from url """

    # Request a download stream
    stream = requests.get(url, stream=True, allow_redirects=True, timeout=20)

    task = DownloadTask(stream, filename)
    task.start()
    return task
