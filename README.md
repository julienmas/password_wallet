---
title: "Pasword Wallet"
contributors: "MASTRANGELO Julien"
---

- [Password Wallet](#password_wallet)
    - [Installation](#installation)
    - [Usage](#usage)
    - [Features](#Features)
    - [Credits](#Credits)


# password_wallet

---

A program to save passwords based on SHA-256 hash function and XOR-encryption.

## installation

---

1. Clone the project :

```
$ git clone https://github.com/julienmas/password_wallet.git
```

2. Installe openssl library : 
```
$ sudo apt-get install libssl-dev
```
3. Choose a master password (of no more than 20 characters) and compute its SHA-256 hash. If you want to use the default password which is '0000', go to 5. (highly unrecommended).

```
$ openssl sha256 your-master-password
```
4. Copy the hash and paste it in stead of the default password hash in line 319 of password_wallet.c (in function checkPassword()).

5. Compile the code password_wallet :

```
$ make
```

6. Start the programm password_wallet:

```
$ ./password_wallet
```

## Usage

---

First, enter the master password chose during installation.
A menu is displayed. Tap the number of your feature's choice, then tap enter.

### Display passwords
### Password generation
### Add password
### Quit

## Features

---

| Feature                                        | Status |
| ---------------------------------------------- | ------ |
| Connection with a master password (breakable)  | ✅     |
| Password generation                            | ✅     |
| Passwords encryption/decryption                | ✅     |
| Manually add a password                        | ✅     |
| Display warning about the strength of a password added | ❌      |
| Remove an account                              | ❌      |
| Sort accounts by alphabetical order            | ❌      |


## Credits

***

The only contributor to this project is :
*Mastrangelo Julien*

<!-- thank people for reviewing the project -->