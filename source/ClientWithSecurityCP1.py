
import pathlib
import socket
import sys
import time
import secrets
import os

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# CP1: Using PKCS#1 v1.5 padding for RSA encryption of file data this is asymetric 
# RSA 1024-bit key → 128-byte blocks; min 11-byte padding → max 117 bytes data per block
MAX_ENCRYPT_BLOCK = 117

def convert_int_to_bytes(x):
    return x.to_bytes(8, "big")

def convert_bytes_to_int(xbytes):
    return int.from_bytes(xbytes, "big")

def send_message(sock, message: bytes):
    sock.sendall(convert_int_to_bytes(len(message)))  # M1: length prefix
    sock.sendall(message)                            # M2: message payload

def receive_message(sock):
    size = convert_bytes_to_int(sock.recv(8))        # M1: read length
    return sock.recv(size)                           # M2: read payload

def authenticate(s):
    # MODE 3: initiating authentication protocol
    print("MODE 3: starting authentication protocol")
    s.sendall(convert_int_to_bytes(3))               # MODE 3 indicator
    print("MODE 3: sent MODE 3 indicator to server")

    # Step 1: send random challenge (M1 + M2)
    client_message = secrets.token_bytes(32)
    print(f"MODE 3: sending challenge ({len(client_message)} bytes)")
    send_message(s, client_message)

    # Step 2: receive signed challenge and certificate
    print("MODE 3: awaiting server's signed challenge and certificate")
    signed_message = receive_message(s)
    print(f"MODE 3: received signed challenge ({len(signed_message)} bytes)")
    server_cert_bytes = receive_message(s)
    print(f"MODE 3: received server certificate ({len(server_cert_bytes)} bytes)")

    # Load CA certificate and verify signature
    with open("source/auth/cacsertificate.crt", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    ca_public_key = ca_cert.public_key()
    try:
        server_cert = x509.load_pem_x509_certificate(server_cert_bytes, default_backend())
        ca_public_key.verify(
            server_cert.signature,
            server_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            server_cert.signature_hash_algorithm,
        )
    except InvalidSignature:
        print("MODE 3: Server certificate NOT signed by CA. Aborting.")
        return None

    # Verify signed challenge
    server_public_key = server_cert.public_key()
    try:
        server_public_key.verify(
            signed_message,
            client_message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature:
        print("MODE 3: Signature mismatch. Aborting.")
        return None

    print("MODE 3: authentication successful.")
    return server_public_key

def main(args):
    
    port = int(args[0]) if len(args) > 0 else 4321
    server_address = args[1] if len(args) > 1 else "localhost"

    start_time = time.time()
    print("Establishing connection to server...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print("Connected to server")

        # Authenticate (MODE 3)
        server_public_key = authenticate(s)
        if not server_public_key:
            print("MODE 2: closing connection due to authentication failure")
            s.sendall(convert_int_to_bytes(2))
            return

        # File‐sending part , hopefullly it sends multiple files 
        while True:
            line = input("Enter filenames to send (space-separated), or -1 to exit: ").strip()
            if line == "-1":
                print("MODE 2: user requested close")
                s.sendall(convert_int_to_bytes(2))
                break

            filenames = line.split()
            # making sure all files exist
            invalid = [f for f in filenames if not pathlib.Path(f).is_file()]
            if invalid:
                print(f"Invalid filenames: {', '.join(invalid)}. Please try again.")
                continue

            # process each file in turn
            for filepath in filenames:
                base = pathlib.Path(filepath).name
                filename_bytes = filepath.encode("utf-8")

                # MODE 0: send filename
                print(f"MODE 0: sending filename '{base}' ({len(filename_bytes)} bytes)")
                s.sendall(convert_int_to_bytes(0))
                s.sendall(convert_int_to_bytes(len(filename_bytes)))
                s.sendall(filename_bytes)

                # MODE 1: encrypt file contents
                with open(filepath, "rb") as fp:
                    data = fp.read()
                print(f"MODE 1: encrypting file '{base}' in blocks of up to {MAX_ENCRYPT_BLOCK} bytes")

                chunks = [data[i:i+MAX_ENCRYPT_BLOCK] for i in range(0, len(data), MAX_ENCRYPT_BLOCK)]
                encrypted_chunks = [server_public_key.encrypt(chunk, padding.PKCS1v15()) for chunk in chunks]
                encrypted_data = b"".join(encrypted_chunks)
                print(f"MODE 1: total encrypted payload size {len(encrypted_data)} bytes")

                # save encrypted to the send_files_enc for server
                os.makedirs("send_files_enc", exist_ok=True)
                enc_path = pathlib.Path("send_files_enc") / f"enc_{base}"
                with open(enc_path, "wb") as ef:
                    ef.write(encrypted_data)
                print(f"MODE 1: saved encrypted file '{enc_path}'")

                # send encrypted payload
                s.sendall(convert_int_to_bytes(1))
                s.sendall(convert_int_to_bytes(len(encrypted_data)))
                s.sendall(encrypted_data)

        print("Closing connection...")
    end_time = time.time()
    print(f"Program took {end_time - start_time:.2f}s to run.")

if __name__ == "__main__":
    main(sys.argv[1:])



