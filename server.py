#!/usr/bin/env python3
import socket
import threading
import sys
import re
import subprocess
import paramiko
from argparse import ArgumentParser


def parsed_args():
    parser = ArgumentParser()
    parser.add_argument('-b', '--bind_host', default='localhost')
    parser.add_argument('-p', '--server_port', default=9999)
    parser.add_argument('-k', '--host_keyfile', default='/home/chris/.ssh/id_rsa')
    return parser.parse_args()


class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_publickey(self, username, key):
        if (username == 'chris') and (key == paramiko.RSAKey(filename='/home/chris/.ssh/id_rsa')):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED


def handle_client(client_socket):
    while True:
        request = client_socket.recv(1024)
        if re.search(b'(exit)', request):
            # client_socket.close()
            client_socket.sendall(b'exiting')
            break
        elif len(request) > 0:
            print('[*] Received: ', request)
            o_put = subprocess.check_output(request.decode(), shell=True)
            client_socket.sendall(o_put)


if __name__ == '__main__':
    args = parsed_args()

    bind_host = args.bind_host
    bind_port = args.server_port
    host_key = paramiko.RSAKey(filename='/home/chris/.ssh/id_rsa')

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind_host, bind_port))
        sock.listen(50)
        print('[+] Listening for connection')
        client, addr = sock.accept()
        print('[*] Accepted connection from {0:s}:{1:d}'.format(addr[0], addr[1]))

    except Exception as e:
        print('[-] Listen failed: {}'.format(str(e)))
        sys.exit(1)

    try:
        with paramiko.Transport(client) as bhSesh:
            bhSesh.add_server_key(host_key)  # servers public key
            s = Server()
            try:
                bhSesh.start_server(server=s)
            except paramiko.SSHException as x:
                print('[-] SSH negotiation failed.')
            with bhSesh.accept(20) as chan:
                print('[+] Authenticated')
                chan.send(bytes('[+] Welcome {}!', 'utf-8'))
                handle_client(chan)

                # multithreaded server loop
                # while True:
                #    client, addr = server.accept()
                #    client_handler = threading.Thread(target=handle_client, args=(client,))
                #    client_handler.start()

    except Exception as e:
        print('[-] Caught exception: {}'.format(str(e)))
        sys.exit(1)
