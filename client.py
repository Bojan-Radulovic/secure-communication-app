import socket
import threading
import sys
import os
from ecdsa import SigningKey, VerifyingKey, BadSignatureError

from cryptography.hazmat.primitives import hashes, poly1305, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.fernet import Fernet
import base64

from cryptography.hazmat.backends import default_backend

def recv_msg():
    #ciscenje unosa
    recved_msg = s.recv(1024)
    while True:
        #cekanje poruke
        recved_msg = s.recv(1024)
        if not recved_msg:
            sys.exit(0)
        try:
            #fernet dekripcija
            recved_msg = f.decrypt(recved_msg)
        except:
            print("Fernet invalid token!")
            sys.exit(0)
        #razdvajanje poruke od autentifikacijskog kod
        msg = recved_msg[:-16]
        recved_hash = recved_msg[-16:]

        #autentifikacija poruke
        p = poly1305.Poly1305(derived_key)
        p.update(msg)
        try:
            p.verify(recved_hash)
            #ispis poruke
            print("Server: " + msg.decode())
            #gasenje programa ako je poruka exit
            if(msg.decode() == "exit"):
                s.shutdown(socket.SHUT_RDWR)
                s.close()
                os._exit(0)
        except:
            print("Message authentication failed!")

def send_msg():
    while True:
        #unos poruke
        sent_msg = input()
        #ovaj kod ukljanja liniju s unosom iz terminala radi vece preglednosti
        print ("\033[A                             \033[A")
        #dodavanje autentifikacijskog koda poruci
        p = poly1305.Poly1305(derived_key)
        p.update(sent_msg.encode())
        sent_hash = p.finalize()
        #slanje poruke i autentifikacijskog koda
        s.send(f.encrypt(sent_msg.encode() + sent_hash))
        #ispis poruke
        print("Client: " + sent_msg)
        #gasenje programa ako je poruka exit
        if(sent_msg == "exit"):
            s.shutdown(socket.SHUT_RDWR)
            s.close()
            os._exit(0)

def generate_keys():
    #generiranje i pohrana ecdsa kljuceva
    sk = SigningKey.generate()
    vk = sk.verifying_key
    with open("client_private.pem", "wb") as f:
        f.write(sk.to_pem())
    with open("client_public.pem", "wb") as f:
        f.write(vk.to_pem())

    #generiranje i pohrana x25519 privatnog kljuca
    client_private_key2 = X25519PrivateKey.generate()
    with open("client_private_x25519.pem", "wb") as f:
        f.write(client_private_key2.private_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))

def start_talk():
    #pokretanje procesa primanja i slanja poruka
    t = threading.Thread(target=recv_msg)
    t.start()
    send_msg()

generate_keys()

#ucitavanje kljuceva i pretvorba u bytes
with open("client_private_x25519.pem", 'rb') as f:
    client_private_key2 = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

client_public_key2 = client_private_key2.public_key()
client_private_bytes = client_private_key2.private_bytes(
            encoding=serialization.Encoding.Raw, 
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption())
client_public_bytes = client_public_key2.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

#definiranje adrese i vrata
host = socket.gethostname()
port = 8080

#povezivanje na server
s = socket.socket()
s.connect((host, port))
print("Client has connected")

#primanje javnog ecdsa kljuca
while True:
    msg = s.recv(1024)
    if not msg:
        sys.exit(0)
    break

vk = VerifyingKey.from_string(msg)
s.send(b"Key recived")

#primanje poruke i potpisa
while True:
    msg = s.recv(1024)
    if not msg:
        sys.exit(0)
    break

recved_msg = msg[:-48]
sig = msg[-48:]

#autentifikacija
try:
    vk.verify(sig, recved_msg)
    print ("Good server signature")
except BadSignatureError:
    print ("BAD SERVER SIGNATURE")
    print ("CLOSING CONNECTION")
    s.shutdown(socket.SHUT_RDWR)
    s.close()
    os._exit(0)

#slanje javnog ecdsa kljuca
vk = VerifyingKey.from_pem(open("client_public.pem").read())
vk = vk.to_string()
s.send(vk)

#cekanje potvrde primanja kljuca
while True:
    msg = s.recv(1024)
    if not msg:
        sys.exit(0)
    break

#slanje poruke i potpisa
with open("client_private.pem") as f:
    sk = SigningKey.from_pem(f.read())
message = b"i Marija"
sig = sk.sign(message)
s.send(message + sig)

#cekanje potvrde uspjesne autentifikacije
while True:
    if not s.recv(1024):
        sys.exit(0)
    break

#slanje javnog x25519 kljuca
s.send(client_public_bytes)

#primanje javnog x25519 kljuca
while True:
    server_public_bytes = s.recv(1024)
    if not server_public_bytes:
        sys.exit(0)
    break

#stvaranje zajednicke tajne
server_public_key2 = X25519PublicKey.from_public_bytes(server_public_bytes)
shared_key = client_private_key2.exchange(server_public_key2)

#derivacija kljuca
derived_key = HKDF(

    algorithm=hashes.SHA256(),

    length=32,

    salt=b"blabla",

    info=b'handshake data',

    backend=default_backend()

).derive(shared_key)

#inicijalizacija fernet enkripcije koristeci zajednicki kljuc
f = Fernet(base64.urlsafe_b64encode(derived_key))

start_talk()

