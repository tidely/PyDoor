""" Checking for certificates and generating new ones """
import logging
import datetime

# Certificate imports
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

# RSA imports
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def load_key(path):
    """ Retrieve a private key """

    try:
        with open(path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
    except Exception as error:
        logging.error('Error loading private key: %s' % str(error))
        return
    else:
        logging.info('Using found private key')
    return private_key


def load_cert(path):
    """ Load a certificate from a file """

    try:
        with open(path, 'rb') as file:
            certificate = x509.load_pem_x509_certificate(
                file.read()
            )
    except Exception as error:
        logging.error('Error loading certificate: %s' % str(error))
        return
    else:
        logging.info('Using found certificate')

    return certificate


def generate_key(path):
    """ Generate a new private key """
    # Generate key
    logging.info('Generating new private keythis might take a while')
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=7680
    )
    # Serialize key
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Save serialized key in file
    with open(path, 'wb') as file:
        file.write(pem)

    return private_key


def generate_certificate(private_key, path):
    """ Generate a certificate from a private key """

    logging.info('Generating new certificate... ')

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
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
    # Write our certificate out to disk.
    with open(path, 'wb') as file:
        file.write(cert.public_bytes(serialization.Encoding.PEM))

    return cert


if __name__ == '__main__':
    key = generate_key('./key.pem')
    generate_certificate(key, './cert.pem')
