import socket
from esocket import ESocket

sock = socket.socket()
sock.connect(('', 6969))

esock = ESocket(sock)


print(esock.recv())