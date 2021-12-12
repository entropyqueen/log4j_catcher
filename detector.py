
import asyncore
import socket
import logging
import time
import json
import sys
import re
import os
from threading import Thread
from phorcys.decoders.deepdecoder import DeepDecoder
from phorcys.inspectors.yara_inspector import YaraInspector

HOST = ''
PORT = 8080

# Create console\stream handler
logging.basicConfig(
    format='%(asctime)s %(levelname)s:%(message)s',
    level=logging.INFO
)
# Create file handler
try:
    os.mkdir('logs')
except FileExistsError:
    pass
fh = logging.FileHandler('logs/catcher.log')
fh.setLevel(logging.INFO)
# Create formatter
formatter = logging.Formatter('%(asctime)s %(levelname)s:%(message)s')
fh.setFormatter(formatter)
# Add the handlers to the root logger
logging.getLogger('').addHandler(fh)


class Handler(asyncore.dispatcher_with_send):
    
    def __init__(self, sock, addr):
        super().__init__(sock)
        self.addr = addr
        self.dd = DeepDecoder()

    def handle_read(self):
        data = self.recv(16384).strip()
        if data:
            if not data:
                return

            layer = self.dd.decode(data)
            inspector = YaraInspector(open('log4j_exploit.yara', 'r').read())
            inspector(layer)
            for leaf in layer.leaves:
                if leaf._matching_rules:
                    for rule in leaf._matching_rules:
                        rule_name = rule.get('rule')
                        if 'Log4Shell' in rule_name:
                            with open(f'logs/logs_{int(time.time())}_data.bin', 'wb') as f:
                                f.write(data)
                            self.analyze_payload(data, leaf.raw_data)

    def analyze_payload(self, data, payload):
        x = re.findall('\$\{.*?\/\/(.*?)\}', payload)
        if len(x) >= 1:
            for p in x:
                logging.info(f'Found payload jndi from {repr(self.addr)}')
                logging.info(f'URL: {p}')
                try:
                    h, p = p.split('/')[0].split(':')
                except:
                    h = p.split('/')[0]
                    p = 389
                Thread(target=self.get_payload, args=[h, int(p)]).start()

    def get_payload(self, h, p):
        try:
            with open(f'logs/logs_{int(time.time())}.bin', 'wb') as f:
                s = socket.socket()
                s.connect((h, p))
                r = s.recv(16384)
                f.write(r)
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

