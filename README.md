# mySNS - Secure File Storage Application

## 1. Overview

The primary goal of this project is to develop a distributed application named **mySNS**. The system is a simplified file storage solution where users can securely store their medical exam reports and prescriptions on a central server. The application includes a server component and a client application that communicates with the server over TCP sockets.

## 2. System Architecture

The project involves the development of two main programs:

- **mySNSServer**: The central server responsible for file storage and management.
- **mySNS Client**: The client application used by users to access and interact with the server from different machines over the Internet.

## 3. Objectives

The system aims to provide secure file storage by implementing various security features:

- Files can be encrypted.
- Files can be signed.
- Files can be sent in a secure envelope.
- Users must authenticate with the system to access their files.

## 4. Commands

### 4.1 Create a User

To create a new user, use the following command:

```sh
mySNS -a <serverAddress> -au <username> <password> <certificateFile>
```

#### Parameters
`<serverAddress>`: The address of the mySNSServer.

`<username>`: The username for the new user.

`<password>`: The password for the new user.

`<certificateFile>`: The file containing the user's certificate.


### 4.2 Send an Encrypted File

To send an encrypted file, use:

```sh
mySNS -a <serverAddress> -m <doctorUsername> -p <password> -u <patientUsername> -sc {<filenames>}+
```

#### Parameters
`<serverAddress>`: The address of the mySNSServer.

`<doctorUsername>`: The doctor's username.

`<password>`: The doctor's password.

`<patientUsername>`: The patient's username.

`{<filenames>}+`: One or more filenames to be encrypted and sent.


### 4.3 Send a Signature

To send a signed file, use:

```sh
mySNS -a <serverAddress> -m <doctorUsername> -p <password> -u <patientUsername> -sa {<filenames>}+
```

#### Parameters
`<serverAddress>`: The address of the mySNSServer.

`<doctorUsername>`: The doctor's username.

`<password>`: The doctor's password.

`<patientUsername>`: The patient's username.

`{<filenames>}+`: One or more filenames to be signed and sent.


### 4.4 Send a Secure Envelope

To send a file in a secure envelope, use:

```sh
mySNS -a <serverAddress> -m <doctorUsername> -p <password> -u <patientUsername> -se {<filenames>}+
```
#### Parameters
`<serverAddress>`: The address of the mySNSServer.

`<doctorUsername>`: The doctor's username.

`<password>`: The doctor's password.

`<patientUsername>`: The patient's username.

`{<filenames>}+`: One or more filenames to be sent in a secure envelope.


### 4.5 Retrieve Files

To retrieve files from the server, use:

```sh
mySNS -a <serverAddress> -u <patientUsername> -p <password> -g {<filenames>}+
```
#### Parameters
`<serverAddress>`: The address of the mySNSServer.

`<patientUsername>`: The patient's username.

`<password>`: The patient's password.

`{<filenames>}+`: One or more filenames to be retrieved.


