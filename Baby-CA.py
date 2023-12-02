import socket
import sys
import datetime
import argparse
import threading
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
listen_flag_port = 3001
allowed_ips = ['192.168.64.14']
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
    # gen cert
    cert_builder = x509.CertificateBuilder().subject_name(
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
        # certificate valid for 3 days
        datetime.datetime.utcnow() + datetime.timedelta(days=3)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )

    # Copy the SAN extension from CSR to the certificate
    san_extension = csr.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    cert_builder = cert_builder.add_extension(san_extension.value, critical=san_extension.critical)

    # Sign and return the certificate
    cert = cert_builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256(), backend=default_backend())
    return cert.public_bytes(serialization.Encoding.PEM)

# initialize flag dictionary. False by default
def generate_flag_dict():
    flag_dict = {}
    for ip_addr in allowed_ips:
        flag_dict.update({ip_addr: False})
    return flag_dict

# listen to listen_port, processing CSR
def listen_CSR(flag_dict):
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the port
    server_address = (listen_addr, listen_port)
    sock.bind(server_address)

    # Listen for incoming connections
    sock.listen(1)

    while True:
        print('CA: Waiting for a connection...')
        connection, client_address = sock.accept()
    
        try:
            print('CA: Connection from', client_address)
        
            # Check if the IP is allowed and flag is not set
            client_ip = str(ip_address(client_address[0]))
            if client_ip in allowed_ips and not flag_dict.get(client_ip, False):
                # Receive the CSR data
                csr_data = connection.recv(2048)
                #print(type(csr_data))
                #print(sys.getsizeof(csr_data))
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
                print(f"CA: IP {client_ip} is either not allowed or flagged.")
                connection.sendall(b'IP not allowed.')
            
        finally:
            # Clean up the connection
            connection.close()

# listen to listen_flag_port, updating flag_dict
# If receive "1" from a ip_addr, update flag_dict[ip_addr] to be True
def listen_flag(flag_dict):
    flag_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    flag_server_address = (listen_addr, listen_flag_port)
    flag_sock.bind(flag_server_address)
    flag_sock.listen(1)

    while True:
        print('Flag server: waiting for a connection...')
        connection, client_address = flag_sock.accept()

        try:
            print('Flag server: connection from', client_address)

            # Check if the IP is allowed
            client_ip = str(ip_address(client_address[0]))
            if client_ip in allowed_ips:
                data = connection.recv(1024).decode()
                print(f"Recv data: {data}")
                if data == "1\n": # echo "1" | nc ca_ip
                    flag_dict[client_ip] = True
                    print(f"Flag server: flag updated for {client_ip}")
            else:
                print('Flag server: connection from unallowed IP:', client_address)
        finally:
            connection.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--flag', action="store_true", help="The CA will constantly receive flags from clinets.")
    args = parser.parse_args()

    flag_dict = generate_flag_dict()

    if args.flag:
        print("Flag value is set as True")
        # Start flag server in a separate thread
        flag_thread = threading.Thread(target=listen_flag, args=(flag_dict,))
        flag_thread.start()
    
    listen_CSR(flag_dict)

if __name__ == "__main__":
    main()
