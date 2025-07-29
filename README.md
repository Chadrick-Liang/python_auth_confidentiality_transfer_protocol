[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/7xa7pSEd)

# 50.005 Programming Assignment 2

This assignment requires knowledge from Network Security and basic knowledge in Python.

## Secure FTP != HTTPs

Note that you will be implementing Secure FTP as your own whole new application layer protocol. In NO WAY we are relying on HTTP/s. Please do not confuse the materials, you don't need to know materials in Week 11 and 12 before getting started.

## Running the code

### Install required modules

This assignment requires Python >3.10 to run.

You can use `pipenv` to create a new virtual environment and install your modules there. If you don't have it, simply install using pip, (assuming your python is aliased as python3):

```
python3 -m pip install pipenv
```

Then start the virtual environment, upgrade pip, and install the required modules:

```
pipenv shell
python -m ensurepip --upgrade
pip install -r requirements.txt
```

If `ensurepip` is not available, you need to install it, e.g with Ubuntu:

```
# Adjust for your python version
sudo apt-get install python3.10-venv
```

### Run `./setup.sh`

Run this in the root project directory:

```
chmod +x ./setup.sh
./setup.sh
```

This will create 3 directories: `/recv_files`, `/recv_files_enc`, and `/send_files_enc` in project's root. They are all empty directories that can't be added in `.git`.

### Run server and client files

In two separate shell sessions, run (assuming you're in root project directory):

```
python3 source/ServerWithoutSecurity.py
```

and:

```
python3 source/ClientWithoutSecurity.py
```

### Using different machines

You can also host the Server file in another computer:

```sh
python3 source/ServerWithoutSecurity.py [PORT] 0.0.0.0
```

The client computer can connect to it using the command:

```sh
python3 source/ClientWithoutSecurity.py [PORT] [SERVER-IP-ADDRESS]
```

### Exiting pipenv shell

To exit pipenv shell, simply type:

```
exit
```

Do not forget to spawn the shell again if you'd like to restart the assignment.

# 🛡️ Secure File Transfer System

This project implements a secure file transfer system using Python sockets and cryptographic authentication via digital certificates and signatures. It contains a client and server that exchange files securely after verifying each other using asymmetric key authentication.

---

## 📁 Directory Structure

```
programming-assignment-2-cl01_team1/
├── source/
│   ├── ClientWithSecurityAP.py         # Client-side script
│   ├── ServerWithSecurityAP.py         # Server-side script
│   └── auth/
│       ├── cacsertificate.crt          # Certificate Authority (CA) cert
│       ├── server_signed.crt           # Server certificate (signed by CA)
│       └── _private_key.pem            # Server's private RSA key
├── files/                              # Files the client sends
│   └── <file_to_send>
├── recv_files/                         # Output folder for received files
```

---

## ⚙️ File Descriptions

### 📤 `ClientWithSecurityAP.py`

This script handles the client-side logic:

- **Establishes a TCP connection** to the server.
- **Initiates authentication (MODE 3)**:
  - Generates a random message.
  - Sends it to the server for signing.
  - Receives the signed message and server certificate.
  - Verifies the server cert with the CA cert.
  - Verifies the signed message with the server's public key.
- **If authentication succeeds**:
  - Prompts the user to input filenames to send.
  - For each file:
    - Sends the filename (MODE 0).
    - Sends the file content (MODE 1).
  - Ends session with MODE 2.

### 📥 `ServerWithSecurityAP.py`

This script handles the server-side logic:

- **Starts a TCP socket** and listens for a client.
- **On connection**, enters a loop and reacts based on `MODE`:
  - **MODE 3** (Authentication):
    - Receives a message.
    - Signs it with the server’s private key.
    - Sends the signed message and server certificate.
  - **MODE 0** (Filename):
    - Receives the filename and stores it temporarily.
  - **MODE 1** (File content):
    - Receives file data.
    - Writes it to `recv_files/recv_<filename>`.
  - **MODE 2** (Close):
    - Closes the socket gracefully.

---

## 🚀 How It Works

### 🔐 Authentication Protocol (MODE 3)

1. **Client** generates a 32-byte random message.
2. **Client → Server**: random message
3. **Server signs message** with its private key.
4. **Server → Client**:
   - Signed message
   - Server’s certificate (signed by CA)
5. **Client verifies**:
   - Server’s certificate is signed by trusted CA (`cacsertificate.crt`)
   - Server signed the original message using private key
6. If both checks succeed, authentication is complete.

---

## 📦 File Transfer Protocols

#### ✅ MODE 0 – Send Filename

- Client sends the filename length + filename as bytes.
- Server reads and stores the name.

#### ✅ MODE 1 – Send File Content

- Client sends the actual file length + file bytes.
- Server writes file to `recv_files/recv_<filename>`.

#### ✅ MODE 2 – Close Connection

- Client sends MODE 2 to tell server to exit loop and close socket.

#### ✅ MODE 3 – Authentication Protocol

- Ensures the server is verified before any data is exchanged.

---

## 📞 Protocol Summary Table

| MODE | Purpose              | Initiator | Description                                         |
| ---- | -------------------- | --------- | --------------------------------------------------- |
| 0    | Send Filename        | Client    | Sends the name of the file to be transferred        |
| 1    | Send File Data       | Client    | Sends the actual file bytes                         |
| 2    | Terminate Connection | Client    | Instructs server to gracefully close the connection |
| 3    | Authentication       | Client    | Validates server identity using cert & signature    |

---

## ✅ Example Run

**Server:**

```
$ python3 source/ServerWithSecurityAP.py
SecureStore Server listening on localhost:4321...
Connection established with ('127.0.0.1', 50000)
Handling MODE 3: Authentication Protocol
✅ Authentication response sent.
Receiving filename...
Finished receiving file in 0.02s!
```

**Client:**

```
$ python3 source/ClientWithSecurityAP.py
Establishing connection to server...
Connected
authentication protocol in progress
Authentication successful.
Enter a filename to send (enter -1 to exit): files/sample.txt
Closing connection...
Program took 1.93s to run.
```

---

## 📌 Notes

- All files **must be placed in** `files/` directory for client to send.
- Server will write files into `recv_files/` (must exist at root level).
- Certificates are read from `source/auth/`.
- Ensure all paths and files exist to avoid runtime errors.

---

## 🔧 Dependencies

Install required packages (inside virtual environment if needed):

```bash
pip3 install cryptography
```

---

## 👨‍💻

- CL01 Team 1
- SUTD – 50.005 Computer System Engineering (Summer 2025)
