
# client.py
import os
import pathlib
import socket
import sys
import time
import secrets
import zlib
import messages
import hashlib
import json

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

MAX_ENCRYPT_BLOCK = 117  # kept for reference but not used with Fernet

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
    print(messages.MESSAGES[lang]["start_auth"])
    s.sendall(convert_int_to_bytes(3))

    client_challenge = secrets.token_bytes(32)
    print(messages.MESSAGES[lang]["send_challenge"])
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
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
    except InvalidSignature:
        print(messages.MESSAGES[lang]["auth_fail"])
        return None

    print(messages.MESSAGES[lang]["auth_success"])
    return srv_pub

def main(args):
    global lang

    # —— LANGUAGE SELECTION —— 
    print("Select language:")
    for key, code in messages.LANG_OPTIONS.items():
        print(f"  {key}. {messages.LANG_NAMES[code]}")
    choice = input("> ").strip()
    lang = messages.LANG_OPTIONS.get(choice, "en")
    print(messages.MESSAGES[lang]["welcome"])

    port = int(args[0]) if args else 4321
    host = args[1] if len(args) > 1 else "localhost"
    start_time = time.time()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))

        # send chosen language to server
        send_message(s, lang.encode("utf-8"))
        print(messages.MESSAGES[lang]["connected"])

        # MODE 3 AUTHENTICATION 
        server_public_key = authenticate(s)
        if not server_public_key:
            s.sendall(convert_int_to_bytes(2))
            return

        # MODE 4: SESSION‐KEY exchange
        session_key = Fernet.generate_key()
        fernet = Fernet(session_key)

        print(messages.MESSAGES[lang]["enc_ses_key"])
        s.sendall(convert_int_to_bytes(4))
        encrypted_skey = server_public_key.encrypt(
            session_key,
            padding.PKCS1v15()
        )
        send_message(s, encrypted_skey)
        print(messages.MESSAGES[lang]["ses_key_sent"])

        #  MODE 0+1: with the multiple file thing
        while True:
            line = input(messages.MESSAGES[lang]["ask_filename"]).strip()
            if line == "-1":
                s.sendall(convert_int_to_bytes(2))
                break

            # allow space-separated file list
            files = line.split()
            invalid = [f for f in files if not pathlib.Path(f).is_file()]
            if invalid:
                print(messages.MESSAGES[lang]["invalid_file"] + ": " + ", ".join(invalid))
                continue

            for fn in files:
                name = pathlib.Path(fn).name.encode("utf-8")
                # MODE 0: send filename
                print(messages.MESSAGES[lang]["sending_file"].format(name.decode()))
                s.sendall(convert_int_to_bytes(0))
                s.sendall(convert_int_to_bytes(len(name)))
                s.sendall(name)

                # read raw file
                raw = open(fn, "rb").read()
                file_hash = hashlib.sha256(raw).hexdigest()
                header = json.dumps({
                    "filename": pathlib.Path(fn).name,
                    "filesize": len(raw),
                    "hash": file_hash
                }).encode("utf-8")
                enc_header = fernet.encrypt(header)
                send_message(s, enc_header)
                print(messages.MESSAGES[lang]["sent_hash_check"])

                enc_reply = receive_message(s)
                reply = fernet.decrypt(enc_reply).decode("utf-8")
                if reply == "SKIP":
                    print(messages.MESSAGES[lang]["client_skip"].format(fn))
                    continue
                else:
                    print(messages.MESSAGES[lang]["client_no_skip"])

                # compress + encrypt payload
                compressed = zlib.compress(raw, level=6)
                print(messages.MESSAGES[lang]["compressed"].format(len(raw), len(compressed)))
                enc = fernet.encrypt(compressed)

                # archive ciphertext 
                os.makedirs("send_files_enc", exist_ok=True)
                with open(f"send_files_enc/enc_{pathlib.Path(fn).name}", "wb") as archive:
                    archive.write(enc)

                # MODE 1: send encrypted 
                print(messages.MESSAGES[lang]["sending_enc"].format(len(enc)))
                s.sendall(convert_int_to_bytes(1))
                s.sendall(convert_int_to_bytes(len(enc)))
                s.sendall(enc)

        print(messages.MESSAGES[lang]["closing"])

    elapsed = time.time() - start_time
    print(messages.MESSAGES[lang]["time"].format(elapsed))

if __name__ == "__main__":
    main(sys.argv[1:])

