
import asyncore
import socket
import logging
import time
import re

import sys
from threading import Thread

HOST = ''
PORT = 8080

# Create console\stream handler
logging.basicConfig(
    format='%(asctime)s %(levelname)s:%(message)s',
    level=logging.DEBUG
)
# Create file handler
fh = logging.FileHandler('catcher.log')
fh.setLevel(logging.DEBUG)
# Create formatter
formatter = logging.Formatter('%(asctime)s %(levelname)s:%(message)s')
fh.setFormatter(formatter)
# Add the handlers to the root logger
logging.getLogger('').addHandler(fh)


class Handler(asyncore.dispatcher_with_send):
    
    def __init__(self, sock, addr):
        super().__init__(sock)
        self.addr = addr

    def handle_read(self):
        data = self.recv(16384)
        if data:
            if not data:
                return
            x = re.findall(b'\$\{.*//(.*)\}', data)
            if len(x) >= 1:
                for p in x:
                    p = p.decode('utf-8')
                    logging.info(f'Found payload jndi from {repr(self.addr)}')
                    logging.info(f'URL: {p}')
                    with open(f'logs_{int(time.time())}_data.bin', 'wb') as f:
                        f.write(data)
                    h, p = p.split('/')[0].split(':')
                    Thread(target=self.get_payload, args=[h, int(p)]).start()

    def get_payload(self, h, p):
        try:
            with open(f'logs_{int(time.time())}.bin', 'wb') as f:
                s = socket.socket()
                s.connect((h, p))
                r = s.recv(4096)
                f.write(r.text)
            s.close()
        except Exception as e:
            logging.error(e)


class Server(asyncore.dispatcher):

    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket()
        self.set_reuse_addr()
        self.bind((HOST, PORT))
        self.listen(1000)

    def handle_accepted(self, sock, addr):
        logging.info('Incoming connection from %s' % repr(addr))
        handler = Handler(sock, addr)


if len(sys.argv) == 2:
    PORT = int(sys.argv[1])

server = Server(HOST, PORT)
asyncore.loop()

