from Crypto.SelfTest.Signature.test_pss import private_key, public_key
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
import hashlib
with open('tex.txt','rb') as mm:
    dt=mm.read()
    k=Fernet.generate_key()



    enc=Fernet(k).encrypt(dt)
    dec=Fernet(k).decrypt(enc)
    print(enc)
    print(dec)
    m=Fernet.generate_key()
    name='meku'
    rt=Fernet(m).encrypt(name.encode())
    dv=Fernet(m).decrypt(rt)
    print(rt)
    print(dv)