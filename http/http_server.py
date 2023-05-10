#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
import double_ratchet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
import base64
import sys


ratchet = double_ratchet.Ratchet()


def get_public_key() -> bytes:
    global ratchet
    return ratchet.getPublicKey()

def decrypt(enc_msg: bytes) -> str:
    global ratchet
    msg = ratchet.decrypt(enc_msg)
    ratchet.updateDH()
    return msg

def pair_comm(pubkey: bytes) -> None:
    global ratchet
    dhpub: dh.DHPublicKey = serialization.load_pem_public_key(pubkey, backend=default_backend())
    ratchet.pairComm(dhpub)

def update_ratchet() -> None:
    global ratchet
    ratchet.updateDH()
    ratchet.getPublicKey().decode('utf-8')
    with open('auth', 'w') as f:
        f.write(get_public_key().decode('ascii'))

def reinit_ratchet() -> None:
    global ratchet
    ratchet = double_ratchet.Ratchet()

def log_message(message):
    with open('keys.log', 'a') as f:
        f.write(message + '\n')


class MyServer(BaseHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        self.__client = None
        super().__init__(*args, **kwargs)

    def __set_response(self):
        path = self.path.replace('/','')
        try:
            with open(path) as f:
                self.send_response(200)
                self.send_header('Content-type','text/html')
                self.end_headers()
                self.wfile.write(bytes(f.read(), 'ascii'))
                f.close()
                return
        except IOError:
            self.send_error(404,'File Not Found: %s' % self.path)

    def do_GET(self):
        #logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        if self.path == '/auth':
            pass
        elif (self.path == '/login') and (self.__client is None):
            self.__client = self.client_address
            key = str(self.headers).split('Session:')[1]
            pubkey = base64.b64decode(key.encode('ascii'))
            logging.info("Client: %s", self.client_address)
            logging.info("New key received")
            pair_comm(pubkey)
            with open('auth', 'w') as f:
                f.write(get_public_key().decode('ascii'))
        elif self.path == '/home':
            b64_msg = str(self.headers).split('Session:')[1]
            enc_msg = base64.b64decode(b64_msg.encode('ascii'))
            msg = decrypt(enc_msg)
            print('Received message: ' + msg)
            log_message(msg)
            update_ratchet()
        elif self.path == '/logout':
            self.__client = None
            reinit_ratchet()
        self.__set_response()

    def do_POST(self):
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        #logging.info("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n", str(self.path), str(self.headers), post_data.decode('utf-8'))
        if self.path == '/home':
            b64_msg = self.rfile.read(content_length) # <--- Gets the data itself
            enc_msg = base64.b64decode(b64_msg)
            msg = decrypt(enc_msg)
            print('Received message: ' + msg)
            log_message(msg)
            update_ratchet()
        self.__set_response()
        #self.wfile.write("POST request for {}".format(self.path).encode('utf-8'))


def run(server_class=HTTPServer, handler_class=MyServer, port=8080):
    logging.basicConfig(level=logging.INFO)
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    logging.info('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping httpd...\n')


from sys import argv

if len(argv) == 2:
    run(port=int(argv[1]))
else:
    run()