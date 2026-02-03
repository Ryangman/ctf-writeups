# CTF League - Nesting and testing

## Flag 1
For this challenge, we were provided with an python obfuscated and encoded python script 
```python
import os;exec(bytes.fromhex("657865632862631.....))
```
With the base64/hex decoding complete, we were left with the following minified python.

```python 
from cryptography.fernet import Fernet;from ast import literal_eval;import hashlib;import struct;import base64 as bs64;import random;import time;import hmac

htp = eval(lambda s,c,d=6:(lambda h:str((struct.unpack('>I',h[(h[-1]&15):(h[-1]&15)+4])[0]&2147483647)%10**d).zfill(d))(hmac.new(s,struct.pack('>Q',c),hashlib.sha1).digest())));

tpt = eval(lambda s,t=30,d=6:htp(bs64.b32decode(s.upper()+'='*((8-len(s)%8)%8)),int(time.time()//t),d));

ctpttk=eval(lambda t:(lambda b:bs64.urlsafe_b64encode(b).decode().encode())(random.getrandbits(256).to_bytes(32,'big') if not random.seed(t) else None));

rfd=eval(lambda p:open(p,'rb').read());

e=eval(lambda p:(lambda k,o,f,d:print(f.encrypt(d).hex()))("J5JVK6ZQNZSV6VDJNVSV6UDBMRZV6ZTJNRWGK4T5",(o:=tpt("J5JVK6ZQNZSV6VDJNVSV6UDBMRZV6ZTJNRWGK4T5")),Fernet(ctpttk(o)),rfd(p)));

print(time.time());
e("flag.txt")
```
While it's mostly undecipherable, we can see that it calls this function `e` on flag.txt, which performs the encryption of the flag.txt which uses the output of `time.time()` (which was provided in the challenge) as a source of randomness, along with the string `J5JVK6ZQNZSV6VDJNVSV6UDBMRZV6ZTJNRWGK4T5`. That secret when decoded from base32 presented the first flag `OSU{0ne_Time_Pads_filler}`

## Flag 2
To find the second flag required actually understanding how the Fernet Encryption worked. De-minifying the encrypt function gave something like this:
```python 
MASTER_SECRET_STR = "J5JVK6ZQNZSV6VDJNVSV6UDBMRZV6ZTJNRWGK4T5"

def e(path: str) -> None:
    # Generate token with Secret STR and time
    token = tpt(MASTER_SECRET_STR)

    # Deterministic
    fernet_key = ctpttk(token)
    f = Fernet(fernet_key)

    # Read plaintext and encrypt
    data = rfd(path)
    ciphertext = f.encrypt(data)

    # Print hex-encoded ciphertext (matches original behavior)
    print(ciphertext.hex())
```
As we had the both the time output and the base32 secret, we had all the elements of randomness to generate the token which is all we need to get the Fernet Key. As Fernet is a Symmetric Key encryption scheme, meaning the key used to encrypt is the same key used to decrypt, getting the key is all we need to read the original plaintext of `flag.txt`

```python
 def decrypt(ctxt: str) -> None:
    # Same as Encryption
    token = tpt(MASTER_SECRET_STR)
    fernet_key = ctpttk(token)
    f = Fernet(fernet_key)
    
    ptext = f.decrypt(bytes.fromhex(ctxt))
    print(ptext)
```
After replacing every use of `time.time()` with our leaked timestamp, we copied the key generation from the encryption scheme, and used the Fernet Decryption function on the ciphertext, which gave us the second flag `b'osu{h4ck1ng_4nd_p4dd1ng}'`.  