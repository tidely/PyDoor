""" Generate SECP521R1 private keys and their corresponding certificate """
import datetime
import logging

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def generate() -> bytes:
    """ Generate a new private key """
    logging.info('Generating new private key')

    private_key = ec.generate_private_key(ec.SECP521R1())
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    return pem

def make_cert(private_key) -> bytes:
    """ Create a certificate from a private key """
    logging.info('Generating new certificate')

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ESocket"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"esocket.com"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 1 year
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    # Sign our certificate with our private key
    ).sign(private_key, hashes.SHA512())

    return cert.public_bytes(serialization.Encoding.PEM)

def load_key(pem) -> ec.EllipticCurvePrivateKey:
    """ Load a private key from PEM format """
    return serialization.load_pem_private_key(pem, password=None)

def load_cert(pem) -> x509.Certificate:
    """ Load certificate from PEM format """
    return x509.load_pem_x509_certificate(pem)


if __name__ == '__main__':

    import os

    KEY_PATH = 'key.pem'
    CERT_PATH = 'cert.pem'

    if not os.path.isfile(KEY_PATH):
        pem_private_key = generate()
        with open(KEY_PATH, 'wb') as file:
            file.write(pem_private_key)
    else:
        with open(KEY_PATH, 'rb') as file:
            pem_private_key = file.read()

    private_key = load_key(pem_private_key)

    if not os.path.isfile(CERT_PATH):
        pem_cert = make_cert(private_key)
        with open(CERT_PATH, 'wb') as file:
            file.write(pem_cert)
    else:
        with open(CERT_PATH, 'rb') as file:
            pem_cert = file.read()

    cert = load_cert(pem_cert)
