"""
    add_user.py - Stores a new username along with salt/password

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    The solution contains the same number of lines (plus imports)
"""

import csv
import os
import hashlib
import Crypto
import pickle

try:
    test = pickle.load(open('passfile.pkl', 'rb'))
except:
    dict_init = {'user': ('salt','hp')}
    pw_dict = open("passfile.pkl","wb")
    pickle.dump(dict_init, pw_dict)
    pw_dict.close()

user = input("Enter a username: ")
password = input("Enter a password: ")

# TODO: Create a salt and hash the password
# salt = ???
# hashed_password = ???

salt = Crypto.Random.get_random_bytes(2)
hashed_password = hashlib.sha512(salt + password)

try:
    pw_file = open("passfile.pkl", 'r')
    pw_dict = pickle.load(pw_file)
    if user in pw_dict:
        print("User already exists!")
        exit(1)
    else:
        pw_dict[user] = (salt, hashed_password)
        print("User successfully added!")
        pickle.dump(pw_dict, pw_file)
        pw_dict.close()
"""
    add_user.py - Stores a new username along with salt/password

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    The solution contains the same number of lines (plus imports)
"""

import csv
import os
import hashlib
import Crypto
import pickle

try:
    test = pickle.load(open('passfile.pkl', 'rb'))
except:
    dict_init = {'user': ('salt','hp')}
    pw_dict = open("passfile.pkl","wb")
    pickle.dump(dict_init, pw_dict)
    pw_dict.close()

user = input("Enter a username: ")
password = input("Enter a password: ")

# TODO: Create a salt and hash the password
# salt = ???
# hashed_password = ???

salt = Crypto.Random.get_random_bytes(2)
hashed_password = hashlib.sha512(salt + password)

try:
    pw_file = open("passfile.pkl", 'r')
    pw_dict = pickle.load(pw_file)
    if user in pw_dict:
        print("User already exists!")
        exit(1)
    else:
        pw_dict[user] = (salt, hashed_password)
        print("User successfully added!")
        pickle.dump(pw_dict, pw_file)
        pw_dict.close()


except FileNotFoundError:
    pass



except FileNotFoundError:
    pass

