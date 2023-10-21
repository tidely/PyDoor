""" Generate EC private keys and corresponding certificates """
import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPublicKeyTypes, CertificateIssuerPrivateKeyTypes
)
from cryptography.hazmat.primitives.asymmetric import ec

# Server Name
SERVER_NAME = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PyDoor"),
    x509.NameAttribute(NameOID.COMMON_NAME, "myserver.com"),
])


def to_pem(obj: ec.EllipticCurvePrivateKey | x509.Certificate) -> None:
    """ Save a private key to a file in PEM format """

    if isinstance(obj, x509.Certificate):
        return obj.public_bytes(serialization.Encoding.PEM)

    if isinstance(obj, ec.EllipticCurvePrivateKey):
        return obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    raise TypeError(f"Invalid type '{type(obj)}'")


def issue_certificate(
        subject_name: x509.Name,
        subject_public_key: CertificateIssuerPublicKeyTypes,
        issuer_name: x509.Name,
        issuer_private_key: CertificateIssuerPrivateKeyTypes,
        valid_for_in_days: int
    ) -> x509.Certificate:
    """Generate a certificate using subject and issuer name,
    subject public key and issuer private key
    """
    certificate = x509.CertificateBuilder().subject_name(
        subject_name
    ).issuer_name(
        issuer_name
    ).public_key(
        subject_public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=valid_for_in_days)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False
    ).sign(
        issuer_private_key, hashes.SHA512()
    )

    return certificate


if __name__ == "__main__":
    # Generate Private Key
    private_key = ec.generate_private_key(ec.SECP521R1)

    # Create self signed certificate (Valid for 10 years)
    cert = issue_certificate(
        SERVER_NAME,
        private_key.public_key(),
        SERVER_NAME,
        private_key,
        valid_for_in_days=365*10
    )

    # Save private key
    with open("private.pem", "wb") as file:
        file.write(to_pem(private_key))

    # Save Certificate
    with open("cert.pem", "wb") as file:
        file.write(to_pem(cert))
