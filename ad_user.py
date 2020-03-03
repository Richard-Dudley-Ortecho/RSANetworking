import bcrypt
user = input("Enter a username: ")
password = input("Enter a password: ")
#print(user)
#print(password)
# TODO: Create a salt and hash the password
# salt = ???
# hashed_password = ???

salt = bcrypt.gensalt()
hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)


try:
    reading = open("passfile.txt" , 'r')
    for line in reading.read().split('\n'):
        if line.split('\t')[0] == user:
            print("User already exists!")
            exit(1)
        reading.close()
except FileNotFoundError:
    pass

salt_u = salt.decode('utf-8')
hashed_password_u = hashed_password.decode('utf-8')

#print(salt_u)
#print(hashed_password_u)

with open("passfile.txt", 'a+') as writer:
    writer.write("{0}\t{1}\t{2}\n".format(user, salt_u, hashed_password_u))
