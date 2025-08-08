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

# Section 3: Sustainability & Inclusivity

## Sustainability 

**1) Optimized File Transfer**

**How it works:** 

**Explanation:** This implementation incorporates sustainability considerations by reducing unnecessary data transfers and optimising network usage. 
Once the secure session key is established between the client and server, the client generates an encrypted hash of the file and sends it to the server for verification. 
If the server detects that an identical file already exists, the transfer is cancelled, preventing redundant uploads and saving bandwidth, processing power, and storage space. 
Additionally, files are compressed before transmission, as seen in the `ClientWithSecurityCP1.py` and `ServerWithSecurityCP2.py` logic, further minimising the amount of data sent over the network. 
These measures lower resource consumption on both client and server systems, aligning with sustainable computing practices.

## Inclusivity 

**1) Multilingual Support**

*Disclaimer: We have only implemented this feature within CP2 due to the lack of time💔*

**How it works:** The feature supports translation to the 4 local languages.
The language is selected based on number being inputted. 1, 2, 3, 4 represent English, Chinese, Tamil & Malay respectively. 

**Explanation:** The client interface is designed with inclusivity in mind, offering full support for four languages.
This multilingual approach ensures that users from diverse linguistic backgrounds can interact with the system comfortably without facing language barriers.
In practice, language-specific message strings are handled within `messages.py`, where message prompts and notifications are mapped to their respective translations. 
This design choice broadens accessibility, allowing the application to be used effectively in multilingual communities and enhancing the overall user experience for a wider audience.
