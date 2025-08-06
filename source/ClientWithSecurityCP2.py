# client.py
import os
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
from cryptography.fernet import Fernet

MAX_ENCRYPT_BLOCK = 117  # unused now but kept for reference

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
    print("MODE 3: starting authentication protocol")
    s.sendall(convert_int_to_bytes(3))
    client_challenge = secrets.token_bytes(32)
    print(f"MODE 3: sending challenge ({len(client_challenge)} bytes)")
    send_message(s, client_challenge)

    signed = receive_message(s)
    cert_bytes = receive_message(s)

    with open("source/auth/cacsertificate.crt", "rb") as f:
        ca = x509.load_pem_x509_certificate(f.read(), default_backend())
    ca_pub = ca.public_key()

    try:
        srv_cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
        ca_pub.verify(
            srv_cert.signature,
            srv_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            srv_cert.signature_hash_algorithm,
        )
        srv_pub = srv_cert.public_key()
        srv_pub.verify(
            signed,
            client_challenge,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature:
        print("MODE 3: authentication failed.")
        return None

    print("MODE 3: authentication successful.")
    return srv_pub

def main(args):
    port = int(args[0]) if args else 4321
    host = args[1] if len(args)>1 else "localhost"
    start = time.time()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print("Connected to server")

        server_public_key = authenticate(s)
        if not server_public_key:
            s.sendall(convert_int_to_bytes(2))
            return

        # —— MODE 4: session‐key handshake —— 
        session_key = Fernet.generate_key()
        fernet = Fernet(session_key)
        print("MODE 4: encrypting and sending session key")
        s.sendall(convert_int_to_bytes(4))
        encrypted_skey = server_public_key.encrypt(
            session_key,
            padding.PKCS1v15()
        )
        send_message(s, encrypted_skey)
        print("MODE 4: session key sent")

        # —— file loop —— 
        while True:
            fn = input("Enter filename to send (-1 to exit): ").strip()
            if fn == "-1":
                s.sendall(convert_int_to_bytes(2))
                break
            if not pathlib.Path(fn).is_file():
                print("Invalid file; try again.")
                continue

            name = pathlib.Path(fn).name.encode()
            print(f"MODE 0: sending filename '{name.decode()}'")
            s.sendall(convert_int_to_bytes(0))
            s.sendall(convert_int_to_bytes(len(name)))
            s.sendall(name)

            # MODE 1: symmetric encrypt file
            # MODE 1: symmetric encrypt file
            data = open(fn, "rb").read()
            enc = fernet.encrypt(data)

            # ── ARCHIVE OF CIPHERTEXT────────────────────────────

            os.makedirs("send_files_enc", exist_ok=True)
            base = pathlib.Path(fn).name
            with open(f"send_files_enc/enc_{base}", "wb") as archive:
                archive.write(enc)
            # ─────────────────────────────────────────────────────────────────

            print(f"MODE 1: sending {len(enc)} bytes of encrypted data")
            s.sendall(convert_int_to_bytes(1))
            s.sendall(convert_int_to_bytes(len(enc)))
            s.sendall(enc)


        print("Closing connection…")
    print(f"Took {time.time()-start:.2f}s")

if __name__ == "__main__":
    main(sys.argv[1:])
