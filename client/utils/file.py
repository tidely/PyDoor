import os


def reverse_readline(filename: str, buf_size: int = 16384) -> str:
    """A generator that returns the lines of a file in reverse order"""

    # Credit: https://stackoverflow.com/a/23646049/10625567

    with open(filename) as file:
        segment = None
        offset = 0
        file.seek(0, os.SEEK_END)
        file_size = remaining_size = file.tell()
        while remaining_size > 0:
            offset = min(file_size, offset + buf_size)
            file.seek(file_size - offset)
            buffer = file.read(min(remaining_size, buf_size))
            remaining_size -= buf_size
            lines = buffer.split('\n')
            if segment is not None:
                if buffer[-1] != '\n':
                    lines[-1] += segment
                else:
                    yield segment
            segment = lines[0]
            for index in range(len(lines) - 1, 0, -1):
                if lines[index]:
                    yield lines[index]
        if segment is not None:
            yield segment