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
import Crypto
from Crypto.Cipher import AES
import socket
import os
from Crypto.PublicKey import RSA
import base64
#from Crypto.Util.Padding import pad
#from Crypto.Util.Padding import unpad


host = "localhost"
port = 10001


# A helper function that you may find useful for AES encryption
# Is this the best way to pad a message?!?!
def pad_message(message):
    return message + " "*((16-len(message))%16)


# Generate a cryptographically random AES key
def generate_key():
    key = Crypto.Random.get_random_bytes(16)
    return key


# Takes an AES session key and encrypts it using the appropriate
# key and return the value
def encrypt_handshake(session_key, public_key):
    #might need to "plain"text the session ke
    sesh = session_key
    #print(sesh)
    encrypt_key = public_key.encrypt(sesh, 32)[0]
    encoded_encrypted_msg = base64.b64encode(encrypt_key)
    return encoded_encrypted_msg


def encrypt_message(message, session_key):
    ciphertext = session_key.encrypt(pad_message(message))
    return ciphertext


# Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key):
    return session_key.decrypt(message)


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
        f = open("./Server/public.pem", 'rb')
        publickey = RSA.importKey(f.read())
        f.close()
    except FileNotFoundError:
        pass


    try:
        # Message that we need to send
        message = user + ' ' + password

        # Generate random AES key
        key = generate_key()
        rand_iv = generate_key()
        AES_key = AES.new(key, AES.MODE_CBC, rand_iv)
        

        iv = base64.b64encode(rand_iv).decode('utf-8')
#        print(type(iv))

        f = open('./Client/iv.txt', 'w')
        f.write(iv)
        f.close()
        print("wrote to iv.txt")

        # Encrypt the session key using server's public keyi
        print("Making handshake")
        encrypted_key = encrypt_handshake(key, publickey)

        # Initiate handshake
        print("Sending handshake")
        send_message(sock, encrypted_key)
        print("Initaited handshake")

        # Listen for okay from server (why is this necessary?)
        if receive_message(sock).decode() != "okay":
            print("Couldn't connect to server")
            exit(0)
        print("Got the OKAY")
        # : Encrypt message and send to server
        uspw = encrypt_message(user + ',' + password, AES_key)
        send_message(sock, uspw)
        print("Sent encrypted username and password")

        # : Receive and decrypt response from server
        success_flag = decrypt_message(receive_message(sock), AES_key)
        #print(success_flag)
        success_flag = success_flag.decode("utf-8")
        success_flag = success_flag.strip()
        if success_flag != "All good":
            print("Wrong username or password")
        else:
            print("Sucess, that is a correct username and password pair")

    finally:
        print('closing socket')
        sock.close()


if __name__ in "__main__":
    main()
