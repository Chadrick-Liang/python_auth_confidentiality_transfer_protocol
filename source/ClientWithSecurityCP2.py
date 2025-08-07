# client.py
import os
import pathlib
import socket
import sys
import time
import secrets
import zlib
import messages
import hashlib, json

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



def main(args):
    global lang
    print("Select language: ")
    for key, code in messages.LANG_OPTIONS.items():
        print(f"     {key}. {messages.LANG_NAMES[code]}")
    choice = input("> ").strip()
    lang = messages.LANG_OPTIONS.get(choice, "en")
    print(messages.MESSAGES[lang]["welcome"])

    port = int(args[0]) if args else 4321
    host = args[1] if len(args)>1 else "localhost"
    start = time.time()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        #send language
        send_message(s, lang.encode("utf-8"))
        print(messages.MESSAGES[lang]["connected"])

        server_public_key = authenticate(s)
        if not server_public_key:
            s.sendall(convert_int_to_bytes(2))
            return

        # —— MODE 4: session‐key handshake —— 
        session_key = Fernet.generate_key()
        fernet = Fernet(session_key)
        #print("MODE 4: encrypting and sending session key")
        print(messages.MESSAGES[lang]["enc_ses_key"])
        s.sendall(convert_int_to_bytes(4))
        encrypted_skey = server_public_key.encrypt(
            session_key,
            padding.PKCS1v15()
        )
        send_message(s, encrypted_skey)
        #print("MODE 4: session key sent")
        print(messages.MESSAGES[lang]["ses_key_sent"])

        # —— file loop —— 
        while True:
            #fn = input("Enter filename to send (-1 to exit): ").strip()
            fn = input(messages.MESSAGES[lang]["ask_filename"]).strip()
            if fn == "-1":
                s.sendall(convert_int_to_bytes(2))
                break
            if not pathlib.Path(fn).is_file():
                #print("Invalid file; try again.")
                print(messages.MESSAGES[lang]["invalid_file"])
                continue

            name = pathlib.Path(fn).name.encode()
            #print(f"MODE 0: sending filename '{name.decode()}'")
            print(messages.MESSAGES[lang]["sending_file"].format(name.decode()))
            s.sendall(convert_int_to_bytes(0))
            s.sendall(convert_int_to_bytes(len(name)))
            s.sendall(name)

            # MODE 1: symmetric encrypt file
            # MODE 1: symmetric encrypt file
            #data = open(fn, "rb").read()
            raw = open(fn, "rb").read()

            #check for duplication
            filename_base = pathlib.Path(fn).name
            file_hash = hashlib.sha256(raw).hexdigest()
            header  = json.dumps({
                "filename": filename_base,
                "filesize": len(raw),
                "hash":     file_hash
            }).encode("utf-8")
            enc_header = fernet.encrypt(header)
            send_message(s, enc_header)
            #print('Just sent the encrypted hash header check')
            print(messages.MESSAGES[lang]["sent_hash_check"])
            enc_reply = receive_message(s)
            reply = fernet.decrypt(enc_reply).decode("utf-8")
            if reply == "SKIP":
                #print(f"{fn} already on server; skipping.")
                print(messages.MESSAGES[lang]["client_skip"].format(fn))
                continue
            else:
                #print('guess i did not receive a skip')
                print(messages.MESSAGES[lang]["client_no_skip"])

            compressed = zlib.compress(raw, level=6)
            #print(f'MODE 1: compressed {len(raw)} to {len(compressed)} bytes')
            print(messages.MESSAGES[lang]["compressed"].format(len(raw), len(compressed)))
            enc = fernet.encrypt(compressed)


            os.makedirs("send_files_enc", exist_ok=True)
            base = pathlib.Path(fn).name
            with open(f"send_files_enc/enc_{base}", "wb") as archive:
                archive.write(enc)

            #print(f"MODE 1: sending {len(enc)} bytes of encrypted data")
            print(messages.MESSAGES[lang]["sending_enc"].format(len(enc)))
            s.sendall(convert_int_to_bytes(1))
            s.sendall(convert_int_to_bytes(len(enc)))
            s.sendall(enc)


        #print("Closing connection…")
        print(messages.MESSAGES[lang]["closing"])
    #print(f"Took {time.time()-start:.2f}s")
    print(messages.MESSAGES[lang]["time"].format(time.time()-start))


def authenticate(s):
    #print("MODE 3: starting authentication protocol")
    print(messages.MESSAGES[lang]["start_auth"])
    s.sendall(convert_int_to_bytes(3))
    client_challenge = secrets.token_bytes(32)
    #print(f"MODE 3: sending challenge ({len(client_challenge)} bytes)")
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
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature:
        #print("MODE 3: authentication failed.")
        print(messages.MESSAGES[lang]["auth_fail"])
        return None

    #print("MODE 3: authentication successful.")
    print(messages.MESSAGES[lang]["auth_success"])
    return srv_pub

if __name__ == "__main__":
    main(sys.argv[1:])
