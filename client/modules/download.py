import logging

import requests

def download(url: str, filename: str) -> None:
    """ Download file from url """

    response = requests.get(url, stream=True, allow_redirects=True)

    with open(filename, "wb") as file:
        for chunk in response.iter_content(chunk_size=10 * 1024):
            file.write(chunk)
