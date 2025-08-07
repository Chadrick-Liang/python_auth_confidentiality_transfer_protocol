# server.py

import pathlib
import os
import socket
import sys
import time
from signal import signal, SIGINT
import zlib
import messages

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

lang = ""

def convert_int_to_bytes(x):
    return x.to_bytes(8, "big")

def convert_bytes_to_int(xbytes):
    return int.from_bytes(xbytes, "big")

def read_bytes(sock, length):
    buf = []
    got = 0
    while got < length:
        chunk = sock.recv(min(length-got, 1024))
        if not chunk:
            raise Exception("Connection broken")
        buf.append(chunk)
        got += len(chunk)
    return b"".join(buf)

def send_message(sock, message: bytes):
    sock.sendall(convert_int_to_bytes(len(message)))
    sock.sendall(message)

def handle_authentication(sock):
    #print("MODE 3: handling authentication")
    print(messages.MESSAGES[lang]["handle_auth"])
    # receive challenge
    cl = convert_bytes_to_int(read_bytes(sock,8))
    challenge = read_bytes(sock, cl)
    # sign
    key_pem = open("source/auth/_private_key.pem","rb").read()
    private = serialization.load_pem_private_key(key_pem, password=None, backend=default_backend())
    signed = private.sign(
        challenge,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    cert = open("source/auth/server_signed.crt","rb").read()
    send_message(sock, signed)
    send_message(sock, cert)

def main(args):
    port = int(args[0]) if args else 4321
    addr = args[1] if len(args)>1 else "localhost"
    session_key = None
    fernet = None

    signal(SIGINT, lambda s,f: sys.exit(0))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((addr, port))
        s.listen()
        print(f"Listening on {addr}:{port}…")

        conn, client = s.accept()
        with conn:
            global lang
            lang_len_bytes = read_bytes(conn, 8)
            lang_len = convert_bytes_to_int(lang_len_bytes)
            lang = read_bytes(conn, lang_len).decode("utf-8")
            if lang not in messages.MESSAGES:
                lang = "en"
            print(messages.MESSAGES[lang]["cli_conn"].format(client))
            filename = None

            while True:
                mode = convert_bytes_to_int(read_bytes(conn,8))
                #print("MODE", mode)
                print(messages.MESSAGES[lang]["MODE"].format(mode))

                if mode == 0:
                    ln = convert_bytes_to_int(read_bytes(conn,8))
                    filename = read_bytes(conn, ln).decode()
                    #print("Received filename:", filename)
                    print(messages.MESSAGES[lang]["rec_file"].format(filename))

                elif mode == 1:
                    #print("MODE 1: receiving encrypted data")
                    print(messages.MESSAGES[lang]["rec_enc"])
                    length = convert_bytes_to_int(read_bytes(conn, 8))
                    enc = read_bytes(conn, length)

                    # ── ARCHIVE THE CIPHERTEXT ───────────────────────────────
                    os.makedirs("recv_files_enc", exist_ok=True)
                    filename_base = pathlib.Path(filename).name
                    with open(f"recv_files_enc/enc_recv_{filename_base}", "wb") as archive:
                        archive.write(enc)
                    # ─────────────────────────────────────────────────────────

                    # now decrypt with Fernet and write plaintext
                    #data = fernet.decrypt(enc)
                    compressed = fernet.decrypt(enc)
                    raw = zlib.decompress(compressed)
                    #print(f"MODE 1: decompressed to from {len(compressed)} to {len(raw)} bytes")
                    print(messages.MESSAGES[lang]["decompressed"].format(len(compressed), len(raw)))
                    os.makedirs("recv_files", exist_ok=True)
                    out = f"recv_files/recv_{filename_base}"
                    with open(out, "wb") as f:
                        f.write(raw)
                    #print("Wrote", out)
                    print(messages.MESSAGES[lang]["wrote"].format(out))

                elif mode == 2:
                    #print("MODE 2: closing")
                    print(messages.MESSAGES[lang]["closing"])
                    break

                elif mode == 3:
                    handle_authentication(conn)

                elif mode == 4:
                    #print("MODE 4: receiving session key")
                    print(messages.MESSAGES[lang]["rec_ses_key"])
                    sk_len = convert_bytes_to_int(read_bytes(conn,8))
                    enc_key = read_bytes(conn, sk_len)
                    key_pem = open("source/auth/_private_key.pem","rb").read()
                    private = serialization.load_pem_private_key(key_pem, password=None, backend=default_backend())
                    session_key = private.decrypt(enc_key, padding.PKCS1v15())
                    fernet = Fernet(session_key)
                    #print("MODE 4: session key established")
                    print(messages.MESSAGES[lang]["ses_key_conf"])

                else:
                    #print("Unknown MODE:", mode)
                    print(messages.MESSAGES[lang]["unknown"].format(mode))

            #print("Shutting down.")
            print(messages.MESSAGES[lang]["shut"])

if __name__ == "__main__":
    main(sys.argv[1:])
