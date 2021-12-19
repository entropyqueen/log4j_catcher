import asyncore
import base64

import requests
import logging
import time
import sys
import re
import os
import pycurl
from io import BytesIO
from threading import Thread
from phorcys.decoders.deepdecoder import DeepDecoder
from phorcys.inspectors.yara_inspector import YaraInspector

HOST = ''
PORT = 8080

dn = {
    b'javaCodeBase': None,
    b'javaFactory': None,
    b'javaClassName': None,
    b'objectClass': None,
    b'javaSerializedData': None,
}

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
        self.inspector = YaraInspector(open('log4j_exploit.yara', 'r').read())

    def handle_read(self):
        data = self.recv(16384).strip()
        if data:
            if not data:
                return

            layer = self.dd.decode(data)
            self.inspector(layer)
            for leaf in layer.leaves:
                if leaf._matching_rules:
                    for rule in leaf._matching_rules:
                        rule_name = rule.get('rule')
                        if 'Log4Shell' in rule_name:
                            with open(f'logs/logs_{int(time.time())}_init.bin', 'wb') as f:
                                f.write(data)
                            self.analyze_payload(data, leaf.raw_data)

    def analyze_payload(self, data, payload):
        x = re.findall('\$\{.*?\/\/(.*?)\}', payload)
        if len(x) >= 1:
            for url in x:
                url = 'ldap://' + url
                logging.info(f'Found payload jndi from {repr(self.addr)}')
                logging.info(f'URL: {url}')
                Thread(target=self.get_payload, args=[url]).start()

    def get_payload(self, url):
        try:
            buff = BytesIO()
            self.curl = pycurl.Curl()
            self.curl.setopt(self.curl.URL, url)
            self.curl.setopt(self.curl.FOLLOWLOCATION, True)
            self.curl.setopt(self.curl.WRITEDATA, buff)
            self.curl.perform()
            self.curl.close()
            buff.seek(0)

            with open(f'logs/logs_{int(time.time())}_ldap.bin', 'wb') as f:
                for line in buff.readlines():
                    line = line.strip()
                    if line:
                        for k in dn.keys():
                            if line.startswith(k):
                                dn[k] = line[len(k):].strip(b':').strip()
                    f.write(line + b'\n')

            if dn[b"javaCodeBase"] is not None and dn[b"javaFactory"] is not None:
                class_url = dn[b"javaCodeBase"] + dn[b"javaFactory"] + b'.class'
                class_url = class_url.decode()
                logging.info(f'Getting: {class_url}')
                r = requests.get(class_url, headers={'User-Agent': 'Java-http-client'})
                with open(f'logs/logs_{int(time.time())}_payload.bin', 'wb') as f:
                    f.write(r.content)
            elif dn[b"javaSerializedData"] is not None:
                with open(f'logs/logs_{int(time.time())}_payload.bin', 'wb') as f:
                    f.write(base64.b64decode(dn[b"javaSerializedData"]))
        except Exception as e:
            logging.error(e)


class Server(asyncore.dispatcher):

    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket()
        self.set_reuse_addr()
        self.bind((HOST, PORT))
        self.listen(1000)
        logging.info(f'Log4j_catcher running on port {PORT}')

    def handle_accepted(self, sock, addr):
        logging.info('Incoming connection from %s' % repr(addr))
        handler = Handler(sock, addr)


if len(sys.argv) == 2:
    PORT = int(sys.argv[1])

server = Server(HOST, PORT)
asyncore.loop()
