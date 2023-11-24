import socket
import os
import argparse
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

# Configuration
baby_ca_address = 'localhost' # change to your CA addr
baby_ca_port = 3000
pri_key = 'node1Pri.key'
csr_name = 'node1.csr'
crt_name = 'node1.crt'

def genPriKey():
    # Generate a private key for Node 1
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Write private key to file
    with open(pri_key, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"Private key for this node generated. Saved as {pri_key} ")

def loadPriKey():
    if os.path.isfile(pri_key):
        with open(pri_key, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
        print(private_key)
        return private_key
    else:
        print("Private key needed. Please generate private key first.\nExit")
        exit()

def reqCert(private_key):
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
    with open(csr_name, 'wb') as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    print(f"CSR saved as {csr_name}")

    # Send the CSR to the Baby CA
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Connect to server and send data
        sock.connect((baby_ca_address, baby_ca_port))
        print("Sending CSR...")
        sock.sendall(csr.public_bytes(serialization.Encoding.PEM))
        print("CSR sent!")

        # Receive data from the server and shut down
        received = sock.recv(2048)
        if len(received) > 20:
            print("Certificate received from Baby CA:")
            # Write received certificate to file
            with open(crt_name, 'wb') as f:
                f.write(received)
            print(f"Certificate saved as {crt_name}")
        else:
            print("Din't receive Certificate from Baby CA!")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-k', '--key', action="store_true", help="Generate Private Key locally")
    parser.add_argument('-r', '--request', action="store_true", help="Construct CSR locally and request CA for cert")
    args = parser.parse_args()
    if args.key:
        genPriKey()
    if args.request:
        private_key = loadPriKey()
        reqCert(private_key)

if __name__ == "__main__":
    main()
