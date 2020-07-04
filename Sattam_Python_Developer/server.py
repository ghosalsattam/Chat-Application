import socket
import select
import threading
from rsa import RSA_Cipher


HEADER_LENGTH = 10
IP = "127.0.0.1"
PORT = 9999

public_key_string = ""


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server_socket.bind((IP, PORT))
server_socket.listen(21)

sockets_list = [server_socket]
clients = {}

rsa_cipher = RSA_Cipher()


def receive_messages(client_socket):
    """
    This function is designed to receive messages from the client.
    Args: client_socket: The client currently the server is interancting.
    """
    try:
        message_header = client_socket.recv(HEADER_LENGTH)

        if not len(message_header):
            return False
        message_length = int(message_header.decode("utf-8").strip())
        message = client_socket.recv(message_length)

        return {"header": message_header, "data": message}

    except:
        pass


def print_message(user, message, rsa_cipher):
    """
    This message aims at printing the desired message on the server terminal.
    Args: message:(dictionary) The details of the message()header and message body.Header contains the body length.
    	  rsa_cipher:The RSA encryption class object, Class responsible for generating public and priivate key.
    """

    message["data"] = int(message["data"].decode("utf-8"))

    message["data"] = str(rsa_cipher.private_key.decrypt(message["data"]))

    message["data"] = int(message["data"]).to_bytes(length=10000, byteorder="big")
    message["data"] = message["data"].decode("utf-8")
    print(str(user["data"].decode("utf-8")) + " > " + str(message["data"]))


def get_server_message(client_socket):
    """
    This function takes CL input from the person sitting at server end.
    Args:client_socket: client inconnection
    """
    x = input("Signzy > ")
    message = {}
    message["data"] = bytes(x.encode("utf-8"))
    message["header"] = bytes((f"{len(x):<{HEADER_LENGTH}}").encode("utf-8"))
    if message is not None:
        client_socket.send(message["header"] + message["data"])


def server_thread():
    """
    This is the main driving function. It registers newly connected users and calls the above methods for previously registered users.
    """
    while True:
        read_sockets, _, exception_sockets = select.select(
            sockets_list, [], sockets_list
        )
        for notified_sockets in read_sockets:

            if notified_sockets == server_socket:
                client_socket, client_address = server_socket.accept()
                user = receive_messages(client_socket)
                rsa_cipher = RSA_Cipher()
                rsa_cipher.generate_key(1024)

                if user is False:
                    continue
                sockets_list.append(client_socket)
                clients[client_socket] = user
                client_socket.send(rsa_cipher.pk)
                print(user["data"].decode("utf-8") + " Connected")

            else:
                message = receive_messages(notified_sockets)

                if message is False:
                    sockets_list.remove(notified_sockets)

                    del clients[notified_sockets]
                    continue
                user = clients[notified_sockets]
                t = threading.Thread(print_message(user, message, rsa_cipher))

                for client_socket in clients:

                    if client_socket == notified_sockets:

                        try:
                            t = threading.Thread(get_server_message(client_socket))
                            t.daemon = True
                        except:
                            pass

        for notified_sockets in exception_sockets:
            sockets_list.remove(notified_sockets)
            del clients[notified_sockets]


server_thread()
