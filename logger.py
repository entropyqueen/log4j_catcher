import base64
import datetime
import os
import uuid
from time import time

from opensearchpy import OpenSearch


class DataLogger:
    def __init__(self):
        self.os_host = os.getenv('OS_HOST', 'localhost')
        self.os_port = os.getenv('OS_PORT', 9200)
        self.os_user = os.getenv('OS_USER', 'admin')
        self.os_password = os.getenv('OS_PASSWORD', 'admin')
        self.index_name = 'log4j-catcher'
        self.os_client = OpenSearch(
            hosts=[{'host': self.os_host, 'port': self.os_port}],
            http_compress=True,
            http_auth=(self.os_user, self.os_password),
            use_ssl=True,
            verify_certs=False,
            ssl_assert_hostname=False,
            ssl_show_warn=False,
        )
        self._create_index()

    def _create_index(self):
        index_body = {
            'settings': {
                'index': {
                    'number_of_shards': 1
                }
            }
        }
        index_mapping = {
            "properties": {
                "contacted_port": {
                    "type": "integer"
                },
                "dn_payload": {
                    "type": "object"
                },
                "incoming_request_headers": {
                    "type": "object"
                },
                "jndi_url": {
                    "type": "text",
                    "fields": {
                        "keyword": {
                            "type": "keyword",
                            "ignore_above": 256
                        }
                    }
                },
                "originating_ip": {
                    "type": "ip"
                },
                "payload": {
                    "type": "text",
                    "fields": {
                        "keyword": {
                            "type": "keyword",
                            "ignore_above": 256
                        }
                    }
                },
                "payload_url": {
                    "type": "text",
                    "fields": {
                        "keyword": {
                            "type": "keyword",
                            "ignore_above": 256
                        }
                    }
                },
                "timestamp": {
                    "type": "date"
                }
            }
        }
        if not self.os_client.indices.exists(self.index_name):
            self.os_client.indices.create(self.index_name, body=index_body)
            self.os_client.indices.put_mapping(index=self.index_name, body=index_mapping)

    def log_event(self,
                  originating_ip: str,
                  contacted_port: int,
                  incoming_request_headers: list,
                  jndi_url: str,
                  dn_payload: dict,
                  payload_url: str,
                  payload: bytes):
        document = {
            'timestamp': datetime.datetime.utcnow(),
            'originating_ip': originating_ip,
            'contacted_port': contacted_port,
            'incoming_request_headers': incoming_request_headers,
            'jndi_url': jndi_url,
            'dn_payload': dn_payload,
            'payload_url': payload_url,
            'payload': base64.b64encode(payload).decode('utf-8'),
        }
        self.os_client.index(
            index=self.index_name,
            body=document,
            id=str(uuid.uuid4()),
            refresh=True
        )


if __name__ == "__main__":
    logger = DataLogger()
    logger.log_event(
        '127.0.0.2',
        2344,
        [{'UA': 'jndi'}],
        '${jndi:ldap://localhost}',
        {'javaFactory': 'DNsd f;oighj sr;iufh'},
        'Payload URL',
        b'pojsoijsoidfj osjdfoijsodfjoj'
    )
