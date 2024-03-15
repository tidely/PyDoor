""" Setup script to build client into exe """
import sys

try:
    from cx_Freeze import setup, Executable
except ImportError:
    print('Missing module "cx_Freeze". Install it using "pip install --upgrade cx_Freeze"')
    sys.exit(1)

BASE = None

if sys.platform == "win32":
    BASE = "Win32GUI"

build_exe_options = {
    # Packages to include
    'includes': [],
    # Files to include
    'include_files': []
}

setup(name="PyDoor",
      version="1.1",
      description="Remote Administration Tool",
      options={'build_exe': build_exe_options},
      executables=[Executable("client.py", base=BASE)])

# python setup.py build
