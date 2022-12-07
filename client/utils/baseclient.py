import sys
import time
import socket
import logging

# Modules
import subprocess
from io import StringIO

from cryptography import x509
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


socket.setdefaulttimeout(10)


class BaseClient:
    """
    Base Client
    """

    # Header length
    header_length = 8

    # Create socket
    sock = socket.socket()
    address = None
    cipher = None

    # Padding for AES
    pad = padding.PKCS7(256)

    def __init__(self, certificate: x509.Certificate) -> None:
        """ Define a trusted certificate """
        self.certificate = certificate

    def connect(self, address: tuple) -> None:
        """ Connect to peer """
        while True:
            try:
                self.sock.connect(address)
            except ConnectionRefusedError:
                # Socket is not open
                continue
            except OSError:
                self.sock.close()
                self.sock = socket.socket()
                self.sock.settimeout(10)
                time.sleep(1)
                continue

            try:
                self.handshake()
            except Exception as error:
                logging.debug('Handshake with peer failed: %s' % str(error))
            else:
                self.address = address
                break

    def handshake(self) -> None:
        """
        Handshake 

        Generate keypair
        Exchange public keys
        Verify signature
        Generate shared session key
        Server sends IV for AES256
        Create AES cipher
        """

        # Keys used for session
        private_key = ec.generate_private_key(ec.SECP521R1())
        pem_public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # Exchange public keys
        serialized_peer_public_key = self._read()
        self._write(pem_public_key)
        signature = self._read()

        # Verify signature
        self.certificate.public_key().verify(
            signature,
            serialized_peer_public_key,
            ec.ECDSA(hashes.SHA512())
        )

        # Exchange private and peer public key for shared key
        peer_public_key = serialization.load_pem_public_key(serialized_peer_public_key)
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

        # Derive key
        derived_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=None,
            info=None
        ).derive(shared_key)

        # Share IV for AES
        iv = self._read()

        self.cipher = Cipher(
            algorithm=algorithms.AES256(derived_key),
            mode=modes.CBC(iv)
        )
        logging.info('Handshake completed successfully')

    def _encrypt(self, data: bytes) -> bytes:
        """ Encrypt data """
        # Pad data
        padder = self.pad.padder()
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
        unpadder = self.pad.unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        return unpadded_data

    def __read(self, amount: int) -> bytes:
        """ Receive raw data from peer """
        data = self.sock.recv(amount)
        if not data:
            # Assume connection was closed
            logging.info('Assuming connection was closed: %s' % str(self.address))
            raise ConnectionResetError

        return data

    def _read(self) -> bytes:
        """ Read messages from client """
        header = self.__read(self.header_length)
        message_length = int.from_bytes(header, 'big')
        return self.__read(message_length)

    def _write(self, data: bytes) -> None:
        """ Write message data to peer """
        # Create header for data
        header = len(data).to_bytes(self.header_length, byteorder='big')
        message = header + data
        self.sock.sendall(message)

    def read(self) -> bytes:
        """ Read encrypted messages from peer """
        return self._decrypt(self._read())

    def write(self, data: bytes) -> bool:
        """ Encrypt and write data to peer """
        return self._write(self._encrypt(data))
