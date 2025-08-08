# Welcome to CL01 Team 1's PA2 GitRepo🥳
This project is the implementation for Programming Assignment 2 of the Computer Systems Engineering module. 
It develops a secure file upload application that enables a client to transfer files to a secure server while ensuring three key security requirements: 

1) authenticating the server’s identity to prevent data leaks to untrusted entities
2) verifying that the server is live before transmission
3) protecting the confidentiality of the data against eavesdropping during transfer

The solution is built in three progressive stages: Authentication Protocol (AP), Confidentiality Protocol 1 (CP1), and Confidentiality Protocol 2 (CP2) which together form a complete custom Secure File Transfer protocol. 
The implementation combines socket programming with cryptographic techniques to provide layered security guarantees.

## ReadME Layout
Section 1: `Running the code`
Instructions on how to compile and run our programs

Section 2: `Uploading multiple files`
Explaining how client can upload multiple files

Section 3: `Sustainability & Inclusivity`
Elaborating on how our team considered sustainability & inclusivity in the assignment

## Section 1: Running the code

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

Before running the files, take note of the following:
1. Replace [PORT] with a number (e.g., 4321).
2. Replace [SERVER-IP] with 127.0.0.1 if running locally, or your server’s LAN/WAN IP if on a network.
3. The order is always: start the server first, then the client.
4. The client will prompt you to choose a file from the /files directory to upload.

To begin, open two separate terminal sessions. Then, run (assuming you're in root project directory):

#### 1) No Security

Server:

```
python3 source/ServerWithoutSecurity.py [PORT] 0.0.0.0
```

Client:

```
python3 source/ClientWithoutSecurity.py [PORT] [SERVER-IP-ADDRESS]
```

#### 2) Authentication Protocol (AP)

Server:

```
python3 source/ServerWithSecurityAP.py [PORT] 0.0.0.0
```

Client:

```
python3 source/ClientWithSecurityAP.py [PORT] [SERVER-IP-ADDRESS]
```

#### 3) Confidentiality Protocol 1 (CP1)

Server:

```
python3 source/ServerWithSecurityCP1.py [PORT] 0.0.0.0
```

Client:

```
python3 source/ClientWithSecurityCP1.py [PORT] [SERVER-IP-ADDRESS]
```

#### 4) Confidentiality Protocol 2 (CP2)

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
