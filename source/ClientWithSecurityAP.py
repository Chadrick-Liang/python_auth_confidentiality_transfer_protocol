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
    print("authentication protocol in progress")

    s.sendall(convert_int_to_bytes(3))  # MODE 3

    # Step 1: Send random message
    client_message = secrets.token_bytes(32)
    send_message(s, client_message)

    # Step 2: Receive signed message and cert
    signed_message = receive_message(s)
    server_cert_bytes = receive_message(s)

    # Load CA cert
    with open("source/auth/cacsertificate.crt", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    ca_public_key = ca_cert.public_key()


    # Verify that server cert is signed by CA
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

    # Extract server public key
    server_public_key = server_cert.public_key()

    # Verify that server signed the message using its private key
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
        print("Signature dont match, aborting now")
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
        print("Connected")

        # Authenticate first
        if not authenticate(s):
            s.sendall(convert_int_to_bytes(2))  # Close connection
            return

        # File sending loop
        while True:
            filename = input("Enter a filename to send (enter -1 to exit): ").strip()

            while filename != "-1" and not pathlib.Path(filename).is_file():
                filename = input("Invalid filename. Please try again: ").strip()

            if filename == "-1":
                s.sendall(convert_int_to_bytes(2))
                break

            filename_bytes = filename.encode("utf-8")

            # Send the filename
            s.sendall(convert_int_to_bytes(0))
            s.sendall(convert_int_to_bytes(len(filename_bytes)))
            s.sendall(filename_bytes)

            # Send the file
            with open(filename, mode="rb") as fp:
                data = fp.read()
                s.sendall(convert_int_to_bytes(1))
                s.sendall(convert_int_to_bytes(len(data)))
                s.sendall(data)

        print("Closing connection...")

    end_time = time.time()
    print(f"Program took {end_time - start_time:.2f}s to run.")


if __name__ == "__main__":
    main(sys.argv[1:])


