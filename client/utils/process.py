import logging

import psutil



def ps() -> list:
    """ List processes running on the system """
    processes = []
    for process in psutil.process_iter():
        processes.append(process.as_dict())
    return processes


def kill(pid: int) -> None:
    """ Kill Process by PID """
    logging.info('Killing process with the pid %s and all its children' % str(pid))
    process = psutil.Process(pid)
    for proc in process.children(recursive=True):
        proc.kill()
        logging.debug('killed child with pid %s' % str(proc.pid))
    process.kill()
    logging.debug('killed parent with pid %s' % str(pid))
