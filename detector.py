
import asyncore
import requests
import logging
import time
import re

import sys
from threading import Thread

HOST = ''
PORT = 8080
nb = 0

logging.basicConfig(format='%(asctime)s %(levelname)s:%(message)s', level=logging.DEBUG)


class Handler(asyncore.dispatcher_with_send):
    
    def __init__(self, sock, addr):
        super().__init__(sock)
        self.addr = addr

    def handle_read(self):
        data = self.recv(16384)
        if data:
            if not data:
                return
            x = re.findall(b'\$\{jndi:.*://(.*)\}', data)
            if len(x) >= 1:
                for p in x:
                    p = p.decode('utf-8')
                    logging.info(f'Found payload jndi from {repr(self.addr)}')
                    logging.info(f'URL: {p}')
                    Thread(target=self.get_payload, args=[p]).start()

    def get_payload(self, p):
        try:
            r = requests.get(f"http://{p}")
            with open('logs_{time.time()}.bin', 'wb') as f:
                f.write(r.text)
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

