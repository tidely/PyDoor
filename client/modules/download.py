""" Download functionality """
import json
import threading

import requests


def download_stream(stream: requests.Response, filename: str, stop_event: threading.Event) -> None:
    """ Download a file from a stream """
    with open(filename, "wb") as file:
        for chunk in stream.iter_content(chunk_size=16384):
            file.write(chunk)
            if stop_event.is_set():
                return

def download(url: str, filename: str) -> None:
    """ Download file from url """

    # Request a download stream
    stream = requests.get(url, stream=True, allow_redirects=True, timeout=20)

    # Create a stop event
    stop_event = threading.Event()

    # Create a thread to download from stream
    thread = threading.Thread(target=download_stream, args=(stream, filename, stop_event))
    thread.stop_event = stop_event
    thread.start()

    # Native ID gets assigned after the thread starts
    thread.name = json.dumps(("download", url, filename, thread.native_id))
