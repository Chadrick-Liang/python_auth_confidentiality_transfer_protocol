

import pathlib
import os
import socket
import sys
import time
from signal import signal, SIGINT
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def convert_int_to_bytes(x):
    return x.to_bytes(8, "big")


def convert_bytes_to_int(xbytes):
    return int.from_bytes(xbytes, "big")


def read_bytes(sock, length):
    buffer = []
    bytes_received = 0
    while bytes_received < length:
        data = sock.recv(min(length - bytes_received, 1024))
        if not data:
            raise Exception("Socket connection broken")
        buffer.append(data)
        bytes_received += len(data)
    return b"".join(buffer)


def send_message(sock, message: bytes):
    sock.sendall(convert_int_to_bytes(len(message)))
    sock.sendall(message)


def handle_authentication(sock):
    # MODE 3: handling authentication protocol
    print("MODE 3: handling authentication request")

    # Step 1: Receive challenge (M1 + M2)
    msg_len = convert_bytes_to_int(read_bytes(sock, 8))
    print(f"MODE 3: received challenge length ({msg_len}) bytes")
    client_message = read_bytes(sock, msg_len)
    print(f"MODE 3: received challenge data ({len(client_message)} bytes)")

    # Step 2: Sign challenge using private key
    with open("source/auth/_private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    signed_message = private_key.sign(
        client_message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    print(f"MODE 3: signed challenge ({len(signed_message)} bytes)")

    # Step 3: Load server certificate
    with open("source/auth/server_signed.crt", "rb") as f:
        cert_data = f.read()
    print(f"MODE 3: loaded server certificate ({len(cert_data)} bytes)")

    # Step 4: Send signed challenge and certificate (two messages)
    send_message(sock, signed_message)
    print("MODE 3: sent signed challenge to client")
    send_message(sock, cert_data)
    print("MODE 3: sent server certificate to client")


def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    address = args[1] if len(args) > 1 else "localhost"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address, port))
            s.listen()
            print(f"SecureStore Server listening on {address}:{port}...")

            client_socket, client_address = s.accept()
            with client_socket:
                print(f"Connection established with {client_address}")

                while True:
                    mode = convert_bytes_to_int(read_bytes(client_socket, 8))
                    print(f"Received MODE {mode}")

                    match mode:
                        case 0:
                            print("MODE 0: receiving filename")
                            filename_len = convert_bytes_to_int(read_bytes(client_socket, 8))
                            filename = read_bytes(client_socket, filename_len).decode("utf-8")
                            print(f"MODE 0: received filename '{filename}'")

                        case 1:
                            print("MODE 1: receiving file data")
                            start_time = time.time()

                            file_len = convert_bytes_to_int(read_bytes(client_socket, 8))
                            file_data = read_bytes(client_socket, file_len)
                            print(f"MODE 1: received data ({file_len} bytes)")

                            filename_base = filename.split("/")[-1]

                            # Decryption omitted here
                            os.makedirs("recv_files", exist_ok=True)
                            with open(f"recv_files/recv_{filename_base}", "wb") as fp:
                                fp.write(file_data)
                            print(f"MODE 1: wrote file 'recv_files/recv_{filename_base}' in {(time.time()-start_time):.2f}s")

                        case 2:
                            print("MODE 2: closing connection")
                            s.close()
                            break

                        case 3:
                            handle_authentication(client_socket)

                        case _:
                            print(f"Unknown MODE: {mode}")

    except Exception as e:
        print(e)
        s.close()


def handler(signal_received, frame):
    print('SIGINT or CTRL-C detected. Exiting gracefully')
    exit(0)

if __name__ == "__main__":
    signal(SIGINT, handler)
    main(sys.argv[1:])
