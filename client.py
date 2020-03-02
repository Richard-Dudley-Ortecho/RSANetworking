"""
    client.py - Connect to an SSL server

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 117
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:
    Richard Dudley Ortecho
    Greg Lennard


"""

import socket
import os
from Crypto.PublicKey import RSA
import base64


host = "localhost"
port = 10001


# A helper function that you may find useful for AES encryption
# Is this the best way to pad a message?!?!
def pad_message(message):
    return message + " "*((16-len(message))%16)


# Generate a cryptographically random AES key
def generate_key():
    return RSA.generate(2048, os.urandom)


# Takes an AES session key and encrypts it using the appropriate
# key and return the value
def encrypt_handshake(session_key, public_key):
    #might need to "plain"text the session ke
    sesh = session_key = session_key.exportKey('DER')
    encrypt_key = public_key.encrypt(sesh, 32)[0]
    encoded_encrypted_msg = base64.b64encode(encrypted_key)
    return encoded_encrypted_msg


# Encrypts the message using AES. Same as server function
def encrypt_message(message, session_key):
    encr_msg = session_key.encrypt(message, 32)[0]
    encoded_encr_msg = base64.b64encode(encr_msg)
    return encoded_encr_msg


# Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key):
    decoded_encrypted_msg = base64.b64decode(message)
    decoded_encrypted_msg = session_key.decrypt(decoded_encrypted_msg)
    return decoded_encrypted_msg


# Sends a message over TCP
def send_message(sock, message):
    sock.sendall(message)


# Receive a message from TCP
def receive_message(sock):
    data = sock.recv(1024)
    return data


def main():
    user = input("What's your username? ")
    password = input("What's your password? ")

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (host, port)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)
    publickey = ""
    try:
        server_public_key = open("./Server/publicKey.txt", 'r')
        publickey = server_public_key.read()
        publickey = RSA.importKey(publickey)
        if(publickey == ""):
            print("No key found!")
        server_public_key.close()
    except FileNotFoundError:
        pass


    try:
        # Message that we need to send
        message = user + ' ' + password

        # Generate random AES key
        key = generate_key()

        # Encrypt the session key using server's public key
        encrypted_key = encrypt_handshake(key, publickey)

        # Initiate handshake
        send_message(sock, encrypted_key)

        # Listen for okay from server (why is this necessary?)
        if receive_message(sock).decode() != "okay":
            print("Couldn't connect to server")
            exit(0)

        # : Encrypt message and send to server
        uspw = encrypt_message(user + ',' + password, key):


        # : Receive and decrypt response from server
        
        if receive_message(sock).decode() != "All good":
            print("Could not parse All good")
            
    finally:
        print('closing socket')
        sock.close()


if __name__ in "__main__":
    main()
