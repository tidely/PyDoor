import sys
from io import StringIO
from typing import Tuple
from utils.errors import errors


def pyshell(command: str) -> Tuple[str, str]:
    """ exec python commands """
    old_stdout = sys.stdout
    redirected_output = sys.stdout = StringIO()
    error = None
    try:
        exec(command)
    except Exception as err:
        error = errors(err, line=False)
    finally:
        sys.stdout = old_stdout
    return redirected_output.getvalue(), error
    
