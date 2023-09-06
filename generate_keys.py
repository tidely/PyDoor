""" Generate SECP521R1 private keys and their corresponding certificate """
import logging

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def generate_keypair() -> bytes:
    """ Generate a new private key """
    logging.info('Generating new private key')

    priv_key = ec.generate_private_key(ec.SECP521R1())
    pub_key = priv_key.public_key()

    private_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


if __name__ == '__main__':

    import os

    PRIVATE_KEY_PATH = 'private.pem'
    PUBLIC_KEY_PATH = 'public.pem'

    # Generate and save keys if they don't exist
    if not os.path.isfile(PRIVATE_KEY_PATH):
        private_bytes, public_bytes = generate_keypair()
        with open(PRIVATE_KEY_PATH, "wb") as file:
            file.write(private_bytes)
        with open(PUBLIC_KEY_PATH, "wb") as file:
            file.write(public_bytes)
    else:
        with open(PRIVATE_KEY_PATH, "rb") as file:
            private_bytes = file.read()
        with open(PUBLIC_KEY_PATH, "rb") as file:
            public_bytes = file.read()

    private_key = serialization.load_pem_private_key(private_bytes, password=None)
    public_key = serialization.load_pem_public_key(public_bytes)
