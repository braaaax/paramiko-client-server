#!/usr/bin/env python3
import sys
import paramiko
from argparse import ArgumentParser


def parsed_args():
    parser = ArgumentParser()
    parser.add_argument('-i', '--ip_address',
                        help='address of ssh server',
                        default='localhost', type=str)
    parser.add_argument('-u', '--user',
                        help='username of client',
                        default='chris', type=str)
    parser.add_argument('-p', '--port',
                        help='port where ssh server listens',
                        default=9999, type=int)
    parser.add_argument('-k', '--key_file',
                        help='filename of private_key',
                        default='/home/chris/.ssh/id_rsa', type=str)
    parser.add_argument('-t', '--known_hosts',
                        help='filename of known hosts',
                        default='/home/chris/.ssh/known_hosts')
    return parser.parse_args()


def ssh_command(ip, user, listing_port, pkey, hosts_file):
    with paramiko.SSHClient() as client:
        client.load_host_keys(hosts_file)
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=user, port=listing_port, pkey=pkey)
        ssh_session = client.get_transport().open_session()
        if ssh_session.active:
            print('[+] client connected')
            while True:
                # receiver
                recv_len = 1
                response = b''
                while recv_len > 0:
                    data = ssh_session.recv(1024)
                    recv_len = len(data)
                    response += data
                    if recv_len < 1024:
                        break
                print(response.decode())

                # sender
                buf = input('> ')
                buf += '\n'
                sendable_buf = bytes(buf, 'utf-8')
                ssh_session.send(sendable_buf)
                if buf == 'exit':
                    ssh_session.close()
                    break

    sys.exit(0)


if __name__ == '__main__':
    args = parsed_args()
    pkey_obj = paramiko.RSAKey(filename=args.key_file)

    ssh_command(args.ip_address, args.user, args.port, pkey_obj, args.known_hosts)
    # rsa_key = paramiko.RSAKey(filename='/home/chris/.ssh/id_rsa')
    # ssh_command('localhost', 'chris', 9999, '/home/chris/.ssh/known_hosts')
