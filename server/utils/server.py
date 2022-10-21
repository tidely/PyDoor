import socket

from esocket import ESocket

sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setblocking(True)

sock.bind(('', 6969))
sock.listen(5)

conn, address = sock.accept()

esock = ESocket(conn, True)

esock.send(b'Successfully opened file.')
