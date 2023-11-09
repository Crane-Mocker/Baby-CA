import socket
import sys
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID
from ipaddress import ip_address

# Configuration
listen_addr = '0.0.0.0'
listen_port = 3000
allowed_ips = ['192.168.1.10', '192.168.1.11', '192.168.1.12', '127.0.0.1']
ca_certificate_path = 'CA.pem'
ca_private_key_path = 'CAPri.key'
ca_private_key_password = b'test'

# Load CA private key
with open(ca_private_key_path, 'rb') as f:
    ca_private_key = load_pem_private_key(f.read(), password=ca_private_key_password, backend=default_backend())

# Load CA certificate
with open(ca_certificate_path, 'rb') as f:
    ca_certificate = x509.load_pem_x509_certificate(f.read(), default_backend())

def generate_certificate(csr_data):
    csr = x509.load_pem_x509_csr(csr_data, default_backend())
    print(csr)
    # Generate certificate
    cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_certificate.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # certificate valid for 365 days
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).sign(ca_private_key, hashes.SHA256(), default_backend())
    
    return cert.public_bytes(serialization.Encoding.PEM)

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the port
server_address = (listen_addr, listen_port)
sock.bind(server_address)

# Listen for incoming connections
sock.listen(1)

while True:
    print('Waiting for a connection...')
    connection, client_address = sock.accept()
    
    try:
        print('Connection from', client_address)
        
        # Check if the IP is allowed
        if str(ip_address(client_address[0])) in allowed_ips:
            # Receive the CSR data
            csr_data = b''
            data = connection.recv(2048)
            #print(type(data))
            #print(sys.getsizeof(data))
            try:
                csr = x509.load_pem_x509_csr(csr_data)
                print('CSR loaded successfully.')
            except ValueError as e:
                print(f'Error loading CSR: {e}')
            #exit()

            # Generate the certificate
            print(f"Generating cert for {client_address}")
            certificate = generate_certificate(csr_data)
            
            # Send the certificate back to the client
            connection.sendall(certificate)
        else:
            print('Connection from unallowed IP:', client_address)
            connection.sendall(b'IP not allowed.')
            
    finally:
        # Clean up the connection
        connection.close()
