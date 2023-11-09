import socket
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

# Configuration
baby_ca_address = 'localhost'
baby_ca_port = 3000

# Generate a private key for Node 1
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Write private key to file
with open('node1Pri.key', 'wb') as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
print("Private key for node 1 generated")

# Create a CSR
print("Creating CSR...")
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    # CSR info
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"c0conut"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"node1.c0conut.com"),
])).add_extension(
    x509.SubjectAlternativeName([x509.DNSName(u"node1.c0conut.com")]),
    critical=False,
    # Sign the CSR with private key.
).sign(private_key, hashes.SHA256())

if isinstance(csr, x509.CertificateSigningRequest):
    print("CSR created.")
else:
    print("CSR creation failed.")

# Write csr to file
with open('node1.csr', 'wb') as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))

# Send the CSR to the Baby CA
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    # Connect to server and send data
    sock.connect((baby_ca_address, baby_ca_port))
    print("Sending CSR...")
    sock.sendall(csr.public_bytes(serialization.Encoding.PEM))
    print("CSR sent!")

    # Receive data from the server and shut down
    received = sock.recv(2048)
    print("Certificate received from Baby CA:")

# Write received certificate to file
with open('node1.crt', 'wb') as f:
    f.write(received)

print("Certificate saved as node1.crt")
