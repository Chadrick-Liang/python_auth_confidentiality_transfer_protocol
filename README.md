# Welcome to CL01 Team 1's PA2 GitRepo🥳
This project is the implementation for Programming Assignment 2 of the Computer Systems Engineering module. 

It develops a secure file upload application that enables a client to transfer files to a secure server while ensuring *three key security requirements:*

1) Authenticating the server’s identity to prevent data leaks to untrusted entities
2) Verifying that the server is live before transmission
3) Protecting the confidentiality of the data against eavesdropping during transfer

The solution is built in *three progressive stages:*

Authentication Protocol (AP), Confidentiality Protocol 1 (CP1), and Confidentiality Protocol 2 (CP2) which together form a complete custom Secure File Transfer protocol. 
The implementation combines socket programming with cryptographic techniques to provide layered security guarantees.

# ReadME Layout
**Section 1:** `Running the code` *(Instructions on how to compile and run our programs)*

**Section 2:** `Uploading multiple files` *(Explaining how client can upload multiple files)*

**Section 3:** `Sustainability & Inclusivity` *(Elaborating on how our team considered sustainability & inclusivity in the assignment)*

# Section 1: Running the code

### Run `./setup.sh`

Run this in the root project directory:
```
chmod +x ./setup.sh
./setup.sh
```

This will create 3 directories: `/recv_files`, `/recv_files_enc`, and `/send_files_enc` in project's root. They are all empty directories that can't be added in `.git`.

### Run server and client files

*⚠️ Before running the files, take note of the following:*

1. Replace [PORT] with a number (e.g., 4321).
2. Replace [SERVER-IP] with 127.0.0.1 if running locally, or your server’s LAN/WAN IP if on a network.
3. The order is always: start the server first, then the client.
4. The client will prompt you to choose a file from the /files directory to upload.

To begin, open two separate terminal sessions. Then, run (assuming you're in root project directory):

### 1) No Security

Server:
```
python3 source/ServerWithoutSecurity.py [PORT] 0.0.0.0
```

Client:
```
python3 source/ClientWithoutSecurity.py [PORT] [SERVER-IP-ADDRESS]
```

### 2) Authentication Protocol (AP)

Server:
```
python3 source/ServerWithSecurityAP.py [PORT] 0.0.0.0
```

Client:
```
python3 source/ClientWithSecurityAP.py [PORT] [SERVER-IP-ADDRESS]
```

### 3) Confidentiality Protocol 1 (CP1)

Server:
```
python3 source/ServerWithSecurityCP1.py [PORT] 0.0.0.0
```

Client:
```
python3 source/ClientWithSecurityCP1.py [PORT] [SERVER-IP-ADDRESS]
```

### 4) Confidentiality Protocol 2 (CP2)

Server:
```
python3 source/ServerWithSecurityCP2.py [PORT] 0.0.0.0
```

Client:
```
python3 source/ClientWithSecurityCP2.py [PORT] [SERVER-IP-ADDRESS]
```

### Using different machines

Server:
```sh
python3 source/ServerWithSecurityCP2.py 4321 0.0.0.0
```

Client:
```sh
python3 source/ClientWithSecurityCP2.py 4321 [SERVER-IP-ADDRESS]
```

### Exiting pipenv shell

To exit pipenv shell, simply type:
```
exit
```

To restart later:
```
pipenv shell
```

# Section 2: Uploading multiple files

**How it works:** In the terminal, input the path directory of the two files while you wish to upload (with a space in between)

For example:
```
files/file.txt files/player.psd
```

**Explanation:** The connection between Server and Client is kept open with respect to the number of files being sent.
On the server side, each incoming file is treated as a separate request within the same session.

**Advantage:** This design ensures that errors or interruptions affecting one file do not impact the transmission of others, while still benefiting from the efficiency of a single persistent connection. 
By combining persistent sessions with per-file request handling, the implementation supports batch uploads more effectively, reducing connection setup time and improving overall throughput.

Client and server share one TCP connection that stays open until you quit.
• You type a list of filenames. 

For each file the client: 

1) Sends its name

2) Encrypts it and sends the ciphertext
• The server reads name → reads ciphertext → decrypts → saves, then loops back for the next file.
• No reconnects between files—everything streams one after another over the same socket.
• When you’re done you type –1, the client sends a “close” message and both sides shut down.

# Section 3: Sustainability & Inclusivity

## Sustainability 

**1) Optimized File Transfer**

*Disclaimer: We have only implemented this feature within CP2 due to the lack of time*

**How it works:** 
The sustainability feature adds an encrypted‐deduplication handshake and transparent compression to every file transfer. 

After a secure session is established, the client computes a SHA-256 digest of the raw file before each payload transfer. It packages the filename, size and digest into a small JSON header, encrypted under the symmetric session key, and sends it to the server. The server decrypts and parses the eader and checks for the filename inside the 'recv_files' folder. It then recomputes a hash value of the potential duplicate file. If the server's copy produces the same digest, it replies "SKIP" and the client aborts the transfer, saving the entire payload.

If the file is new or has changed, the client proceeds to compress the raw bytes with zlib, encrypts the compressed blob, and streams it. The server then decrypts and decompresses the data, storing it under recv_files.

**Explanation:** This implementation incorporates sustainability considerations by reducing unnecessary data transfers and optimising network usage. 
By replacing needless transmimssions with a tiny encrypted header and applying lightweight compression to the actual payload, we minimize overall energy consumption, total bandwith use, CPU and memory utilization, making every transfer as lean and efficient as possible.

## Inclusivity 

**1) Multilingual Support**

*Disclaimer: We have only implemented this feature within CP2 due to the lack of time*

**How it works:** On startup, the client presents a simple menu of 4 supported languages (English, 中文, தமிழ், Bahasa Melayu) by reading from a shared messages.py dictionary module. The user enters a number (1–4), which the client maps to a language code ("en", "zh", "ta", "ms"). Immediately after opening the TCP connection, the client sends the chosen code where it is assigned to a global lang variable on both client and server.

From then on, both sides import strings from the MESSAGES dictionary in messages.py, containing all user-facing text, keyed by the language code and message ID. All prompts, errors, and logs flow through this lookup table, so adding a new language is as simple as dropping in a new translation block in messages.py.


**Explanation:** The client interface is designed with inclusivity in mind, offering full support for four languages.
This multilingual approach ensures that users from diverse linguistic backgrounds can interact with the system comfortably without facing language barriers 
This design choice broadens accessibility, allowing the application to be used effectively in multilingual communities and enhancing the overall user experience for a wider audience.
