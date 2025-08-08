
# client.py
import pathlib
import socket
import sys
import time
import secrets

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def convert_int_to_bytes(x):
    return x.to_bytes(8, "big")


def convert_bytes_to_int(xbytes):
    return int.from_bytes(xbytes, "big")


def send_message(sock, message: bytes):
    sock.sendall(convert_int_to_bytes(len(message)))
    sock.sendall(message)


def receive_message(sock):
    size = convert_bytes_to_int(sock.recv(8))
    return sock.recv(size)


def authenticate(s):
    # MODE 3: initiating authentication protocol
    print("MODE 3: starting authentication protocol")
    s.sendall(convert_int_to_bytes(3))  # MODE 3 indicator

    # Step 1: Send random challenge to server (M1 + M2)
    client_message = secrets.token_bytes(32)
    print(f"MODE 3: sending challenge ({len(client_message)} bytes)")
    send_message(s, client_message)

    # Step 2: Receive signed message and certificate (two send_message calls)
    print("MODE 3: awaiting server's signed challenge and certificate")
    signed_message = receive_message(s)
    print(f"MODE 3: received signed challenge ({len(signed_message)} bytes)")
    server_cert_bytes = receive_message(s)
    print(f"MODE 3: received server certificate ({len(server_cert_bytes)} bytes)")

    # Load CA cert and verify server certificate signature
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
        print("Server certificate NOT signed by CA. Aborting.")
        return False

    # Extract server public key and verify signature
    server_public_key = server_cert.public_key()
    try:
        server_public_key.verify(
            signed_message,
            client_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except InvalidSignature:
        print("Signature mismatch. Aborting.")
        return False

    print("Authentication successful.")
    return True


def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    server_address = args[1] if len(args) > 1 else "localhost"

    start_time = time.time()
    print("Establishing connection to server...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print("Connected to server")

        # MODE 3: Authenticate
        if not authenticate(s):
            print("MODE 2: closing connection due to authentication failure")
            s.sendall(convert_int_to_bytes(2))  # MODE 2: close
            return

        # File sending loop (supports multiple files per line)
        while True:
            raw = input("Enter filenames (separated by spaces), or -1 to exit: ").strip()
            if raw == "-1":
                print("MODE 2: user requested close")
                s.sendall(convert_int_to_bytes(2))  # MODE 2: close
                break

            filenames = raw.split()
            for fn in filenames:
                p = pathlib.Path(fn)
                if not p.is_file():
                    print(f"  ✗ '{fn}' not found; skipping.")
                    continue

                base = p.name
                data = p.read_bytes()

                # MODE 0: send filename
                print(f"MODE 0: sending filename '{base}' ({len(base.encode())} bytes)")
                s.sendall(convert_int_to_bytes(0))
                send_message(s, base.encode())

                # MODE 1: send file data
                print(f"MODE 1: sending file data ({len(data)} bytes)")
                s.sendall(convert_int_to_bytes(1))
                send_message(s, data)

        print("Closing connection...")
    end_time = time.time()
    print(f"Program took {end_time - start_time:.2f}s to run.")


if __name__ == "__main__":
    main(sys.argv[1:])
