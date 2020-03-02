"""
    server.py - host an SSL server that checks passwords

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 140
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:

    Richard Dudley Ortecho

"""

import socket
from Crypto.PublicKey import RSA
import os
import base64
import bcrypt

host = "localhost"
port = 10001


# A helper function. It may come in handy when performing symmetric encryption
def pad_message(message):
    return message + " " * ((16 - len(message)) % 16)


# Generate the server's public and private key and store in Server folder
def generate_server_keys():
    size_key = 256*4
    privatekey = RSA.generate(size_key, os.urandom)
    publickey = privatekey.publickey()
    f = open('./Server/public.pem', 'wb')
    f.write(publickey.exportKey('PEM'))
    f.close()
    #f.write(public_plain)
    #pub_file.close()
    return privatekey

# Write a function that decrypts a message using the server's private key
def decrypt_key(message, private_key):
    d_e_msg = base64.b64decode(message)
    d_e_msg = private_key.decrypt(d_e_msg)
    return d_e_msg

def encrypt_message(message, session_key):
    encr_msg = session_key.encrypt(message, 32)[0]
    encoded_encr_msg = base64.b64encode(encr_msg)
    return encoded_encr_msg


# Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key):
    decoded_encrypted_msg = base64.b64decode(message)
    decoded_encrypted_msg = session_key.decrypt(decoded_encrypted_msg)
    return decoded_encrypted_msg


# Receive 1024 bytes from the client
def receive_message(connection):
    return connection.recv(1024)


# Sends message to client
def send_message(connection, data):
    if not data:
        print("Can't send empty string")
        return
    if type(data) != bytes:
        data = data.encode()
    connection.sendall(data)


# A function that reads in the password file, salts and hashes the password, and
# checks the stored hash of the password to see if they are equal. It returns
# True if they are and False if they aren't. The delimiters are newlines and tabs
def verify_hash(user, password):
    try:
        reader = open("passfile.txt", 'r')
        for line in reader.read().split('\n'):
            line = line.split("\t")
            if line[0] == user:
                salt = user + "1"
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt.encode('utf-8'))   
                return hashed_password == line[2]
        reader.close()
    except FileNotFoundError:
        return False
    return False


def main():
    # Set up network connection listener
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    print('starting up on {} port {}'.format(*server_address))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(server_address)
    sock.listen(1)
    #make a server private and public key and store in the Server Folder
    privatekey = generate_server_keys()
    try:
        while True:
            # Wait for a connection
            print('waiting for a connection')
            connection, client_address = sock.accept()
            try:
                print('connection from', client_address)

                
                # Receive encrypted key from client
                encrypted_key = receive_message(connection)

                # Send okay back to client
                send_message(connection, "okay")

                # Decrypt key from client
                plaintext_key = decrypt_key(encrypted_key, privatekey)

                # Receive encrypted message from client
                ciphertext_message = receive_message(connection)

                #: Decrypt message from client
                text_key = RSA.importKey(plaintext_key)
                response =  decrypt_message(ciphertext_message, text_key)
    
                # : Split response from user into the username and password
                re = response.split(",")
                username = re[0]
                password = re[1]
                
                #: Encrypt response to client
                
                check = verify_hash(username, password)

                if(check != False):
                    ciphertext_response = "All good"
                    ciphertext_response = encrypt_message(ciphertext_response, text_key)
                else:
                    ciphertext_response = "Something went bad"
                    ciphertext_response = encrypt_message(ciphertext_response, text_key)

                # Send encrypted response
                send_message(connection, ciphertext_response)
            finally:
                # Clean up the connection
                connection.close()
    finally:
        sock.close()


if __name__ in "__main__":
    main()
