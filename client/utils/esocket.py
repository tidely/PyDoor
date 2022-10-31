import os
import socket
import logging
from typing import Tuple, Union
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class ESocket:
    """
    Encrypted Socket

    Perform ECDH with the peer, agreeing on a session key, which is then used for AES256 encryption

    Header has a set size (default: 16 bytes) and consists of 3 data points
    The first byte determines if the packet is multipacket (is split into multiple packets)
    The second byte determines if the data is an error
    The rest of the header is used to set the size of the incoming data
    """

    # Byte length of the complete header
    header_length = 16
    # Byte length of the size header
    size_header_length = header_length - 2

    # AES encryption
    encryptor = None
    decryptor = None

    # Padding for AES encryption
    _pad = padding.PKCS7(256)

    def __init__(self, sock: socket.socket, server: bool = False) -> None:
        """ Define variables """
        self.sock = sock
        self.server = server

        self.handshake()

    def close(self):
        """ Close socket """
        self.sock.close()

    def encrypt(self, data: bytes) -> bytes:
        """ Encrypt data """
        padder = self._pad.padder()
        data = padder.update(data) + padder.finalize()

        encryptor = self._cipher.encryptor()
        data = encryptor.update(data) + encryptor.finalize()
    
        return data

    def decrypt(self, data: bytes) -> bytes:
        """ Decrypt data """

        decryptor = self._cipher.decryptor()
        data = decryptor.update(data) + decryptor.finalize()

        unpadder = self._pad.unpadder()
        data = unpadder.update(data) + unpadder.finalize()

        return data

    def handshake(self) -> bool:
        """
        Handshake with Client

        Uses ECDH to agree on a session key
        Session key is used for AES256 encryption
        """

        # Use ECDH to derive a key for fernet encryption

        private_key = ec.generate_private_key(ec.SECP521R1())

        serialized_public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Exchange public keys
        logging.debug('retrieving peer public key')
        if self.server:
            self._send(serialized_public_key)
            _, serialized_peer_public_key = self._recv()
        else:
            _, serialized_peer_public_key = self._recv()
            self._send(serialized_public_key)

        peer_public_key = serialization.load_pem_public_key(serialized_peer_public_key)

        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

        # Perform key derivation.

        derived_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=None,
            info=None
        ).derive(shared_key)

        logging.debug('agreeing on iv with peer')
        if self.server:
            iv = os.urandom(16)
            self._send(iv)
        else:
            _, iv = self._recv()

        self._cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))

        return True

    def make_header(self, data: bytes, error: str) -> Tuple[bytes, Union[bytes, None]]:
        """ Make header for data """

        if len(error) > 1:
            raise

        split = 0
        extra_data = None
        packet_data = data

        max_data_size = int('9' * self.size_header_length)

        if len(data) > max_data_size:
            split = 1
            packet_data = data[:max_data_size]
            extra_data = data[max_data_size+1:]

        size_header = f'{len(packet_data)}'

        if len(size_header) < self.size_header_length:
            # Pad extra zeros to size header
            size_header = '0' * (self.size_header_length - len(size_header)) + size_header

        packet = f'{split}{error}{size_header}'.encode() + packet_data

        return packet, extra_data

    def parse_header(self, header: bytes) -> Tuple[bool, str, int]:
        """ Parse esocket header """

        multipacket = bool(int(chr(header[0])))
        error = chr(header[1])
        size_header = int(header[2:])

        return multipacket, error, size_header

    def _recv(self) -> Tuple[str, bytes]:
        """ Receive data from client """

        def recvall(amount: int) -> bytes:
            """ Receive x amount of bytes """
            data = b''
            while len(data) < amount:
                data += self.sock.recv(amount - len(data))
            return data

        header = recvall(self.header_length)
        multipacket, error, size_header = self.parse_header(header)
        logging.debug(f'parsed header: {multipacket}/{error}/{size_header}')

        data = recvall(size_header)
        logging.debug('got packet')

        if multipacket:
            _, next_data = self._recv()
            return error, data + next_data

        return error, data

    def postrecv(self, data: bytes) -> bytes:
        """ Post-receive decryption """
        return self.decrypt(data)

    def recv(self) -> Tuple[str, bytes]:
        """ Receive data from client """
        error, data = self._recv()
        return error, self.postrecv(data)

    def _send(self, data: bytes, error: str = '0') -> None:
        """ Send data to client """

        packet, extra_data = self.make_header(data, error)

        self.sock.send(packet)
        logging.debug('sent packet')
        if extra_data:
            self._send(extra_data)

    def presend(self, data: bytes) -> bytes:
        """ Pre-send encryption """
        # Pad data
        return self.encrypt(data)

    def send(self, data: bytes, error: str = '0') -> None:
        """ Send data to client """
        self._send(self.presend(data), error)
