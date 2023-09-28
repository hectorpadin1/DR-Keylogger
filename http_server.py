#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
import double_ratchet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from os import system
import base64
from secrets import token_urlsafe

'''
TODO: fully support multiclient
'''

SERVER_IP = "localhost"
SERVER_PORT = 8000

ratchet = double_ratchet.Ratchet()
clients = []


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

def update_ratchet(token: str) -> None:
    global ratchet
    ratchet.updateDH()
    ratchet.getPublicKey().decode('utf-8')
    with open(token, 'w') as f:
        f.write(get_public_key().decode('ascii'))

def reinit_ratchet() -> None:
    global ratchet
    ratchet = double_ratchet.Ratchet()


class MyServer(BaseHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        self.client = None
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        return

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
        global clients
        ip = self.client_address[0]
        f_path = "logs/" + ip
        if (self.path == '/login'):
            # received a new connection
            if not any(ip in cp for cp in clients):
                clients.append({ip, token_urlsafe(16)})
                print("Client connected: ", ip)
                system("date >> "+f_path+";echo 'Client connected' >> " + f_path)
            # old connections can call login endpoint to renew their keys
            # update/create the client key
            print("Renewing keys")
            key = str(self.headers).split('Session:')[1]
            pubkey = base64.b64decode(key.encode('ascii'))
            pair_comm(pubkey)
            # just update the public key under a the random client endpoint
            token = list([d for d in clients if ip in d][0])[1]
            with open(token, 'w') as f:
                f.write(get_public_key().decode('ascii'))
            # send endpoint to client
            self.send_response(200)
            self.send_header('Content-type','text/html')
            self.send_header('Location', token)
            self.end_headers()
            self.wfile.write(bytes(token, 'ascii'))

        elif self.path == '/logout':
            # client disconnected due to an error
            clients = [d for d in clients if ip not in d]
            print("Client disconnected: ", ip)
            reinit_ratchet()
            system("date >> "+f_path+";echo 'Client disconnected' >> " + f_path)
        self.__set_response()

    def do_POST(self):
        global clients
        ip = self.client_address[0]
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        #logging.info("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n", str(self.path), str(self.headers), post_data.decode('utf-8'))
        if self.path == '/home':
            f_path = "logs/" + ip
            b64_msg = self.rfile.read(content_length) # <--- Gets the data itself
            enc_msg = base64.b64decode(b64_msg)
            msg = decrypt(enc_msg)
            print(ip + ': ' + msg)
            system("date >> "+f_path+";echo '"+msg+"' >> " + f_path)
            token = list([d for d in clients if ip in d][0])[1]
            update_ratchet(token)
        self.__set_response()


def run(server_class=HTTPServer, handler_class=MyServer):
    logging.basicConfig(level=logging.INFO)
    server_address = (SERVER_IP, SERVER_PORT)
    httpd = server_class(server_address, handler_class)
    logging.info('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping httpd...\n')


run()