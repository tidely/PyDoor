import time
import socket
import select
import logging

from cryptography import x509
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


logging.basicConfig(level=logging.DEBUG)


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
                logging.debug('Already connected to peer, attempting reconnect')
                self.sock.close()
                self.sock = socket.socket()
                time.sleep(1)
                continue
            try:
                self.handshake()
            except Exception as error:
                logging.debug('Handshake with peer failed: %s' % str(error))
            else:
                self.address = address
                break

    def handshake(self, _blocking: bool = True) -> None:
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

        serialized_peer_public_key = self._read(blocking=_blocking)
        self._write(pem_public_key, blocking=_blocking)
        signature = self._read(blocking=_blocking)

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
        iv = self._read(blocking=_blocking)

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

    def __read(self, amount: int, blocking: bool = False) -> bytes:
        """ Receive raw data from peer """
        while True:
            # Check if socket is readable
            readable, _, errors = select.select([self.sock], [self.sock], [self.sock])
            if errors:
                raise OSError('Could not read from socket: %s' % str(self.address))
            if readable:
                # Read of socket
                data = self.sock.recv(amount)
                if data:
                    return data
                else:
                    # Assume socket is closed
                    logging.debug('Assuming socket is closed')
                    raise ConnectionResetError('Connection closed by peer')
            # Only run the loop once if blocking is set to False
            if not blocking:
                break

        raise TimeoutError('Could not read from socket: %s' % str(self.address))

    def _read(self, blocking: bool = False) -> bytes:
        """ Read messages from client """
        header = self.__read(self.header_length, blocking=blocking)
        message_length = int.from_bytes(header, 'big')
        return self.__read(message_length, blocking=blocking)

    def _write(self, data: bytes, blocking: bool = False) -> None:
        """ Write message data to peer """
        # Create header for data
        header = len(data).to_bytes(self.header_length, byteorder='big')
        message = header + data
        while True:
            # Check if socket is readable
            _, writeable, errors = select.select([self.sock], [self.sock], [self.sock])
            if errors:
                break
            if writeable:
                # Write to socket
                self.sock.sendall(message)
                return

            # Only run the loop once if blocking is set to False
            if not blocking:
                break

        raise OSError('Could not write to socket: %s' % str(self.sock))

    def read(self, blocking: bool = False) -> bytes:
        """ Read encrypted messages from peer """
        return self._decrypt(self._read(blocking=blocking))

    def write(self, data: bytes, blocking: bool = False) -> bool:
        """ Encrypt and write data to peer """
        return self._write(self._encrypt(data), blocking=blocking)


class Client(BaseClient):
    """ Client for managing commands """

    def __init__(self, certificate: x509.Certificate) -> None:
        super().__init__(certificate)

    def listen(self) -> None:
        """ Listen for coming commands """
        # Wait for a command to arrive
        command = self.read(blocking=True).decode()
        match command:
            case 'SHELL':
                self.shell()
            case 'PYTHON':
                self.interpreter()
            case _:
                logging.debug('Received unrecognized command: %s' % command)

    def shell(self) -> None:
        """ Open a shell for peer """
        command = self.read(blocking=True).decode()
        logging.debug('Executing shell command: %s' % command)
        self.write(b'You made it!')

    def interpreter(self) -> None:
        """ Open python interpreter for peer """

if __name__ == '__main__':
    with open('cert.pem', 'rb') as file:
        cert = x509.load_pem_x509_certificate(file.read())

    client = Client(cert)
    client.connect(('localhost', 6969))
    print(client.read(blocking=True))
    client._write(b'hello lol')

    while True:
        client.listen()
