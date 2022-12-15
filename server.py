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
    while True:
        #cekanje poruke
        recved_msg = conn.recv(1024)
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
            print("Client: " + msg.decode())
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
        conn.send(f.encrypt(sent_msg.encode() + sent_hash))
        #ispis poruke
        print("Server: " + sent_msg)
        #gasenje programa ako je poruka exit
        if(sent_msg == "exit"):
            s.shutdown(socket.SHUT_RDWR)
            s.close()
            os._exit(0)

def generate_keys():
    #generiranje i pohrana ecdsa kljuceva
    sk = SigningKey.generate()
    vk = sk.verifying_key
    with open("server_private.pem", "wb") as f:
        f.write(sk.to_pem())
    with open("server_public.pem", "wb") as f:
        f.write(vk.to_pem())

    #generiranje i pohrana x25519 privatnog kljuca
    server_private_key2 = X25519PrivateKey.generate()
    with open("server_private_x25519.pem", "wb") as f:
        f.write(server_private_key2.private_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))

def start_talk():
    #slanje pozdravne poruke
    conn.send("Welcome to the server".encode())
    #pokretanje procesa primanja i slanja poruka
    t = threading.Thread(target=recv_msg)
    t.start()
    send_msg()

generate_keys()

#ucitavanje kljuceva i pretvorba u bytes
with open("server_private_x25519.pem", 'rb') as f:
    server_private_key2 = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    
server_public_key2 = server_private_key2.public_key()
server_private_bytes = server_private_key2.private_bytes(
            encoding=serialization.Encoding.Raw, 
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption())
server_public_bytes = server_public_key2.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

#definiranje adrese i vrata
host = socket.gethostname()
port = 8080

s = socket.socket()
s.bind((host, port))
s.listen(1)

#cekanje na povezivanje klijenta
print("Waiting for connections")
conn, addr = s.accept()

print("Client has connected")

#slanje javnog ecdsa kljuca
vk = VerifyingKey.from_pem(open("server_public.pem").read())
vk = vk.to_string()
conn.send(vk)

#cekanje potvrde primanja kljuca
while True:
    msg = conn.recv(1024)
    if not msg:
        sys.exit(0)
    break

#slanje poruke i potpisa
with open("server_private.pem") as f:
    sk = SigningKey.from_pem(f.read())
message = b"Hvaljen Isus"
sig = sk.sign(message)
conn.send(message + sig)

#primanje javnog ecdsa kljuca
while True:
    msg = conn.recv(1024)
    if not msg:
        sys.exit(0)
    break

vk = VerifyingKey.from_string(msg)
conn.send(b"Key recived")

#primanje poruke i potpisa
while True:
    msg = conn.recv(1024)
    if not msg:
        sys.exit(0)
    break

recved_msg = msg[:-48]
sig = msg[-48:]

#autentifikacija
try:
    vk.verify(sig, recved_msg)
    print ("Good client signature")
    conn.send(b"Good client signature")
except BadSignatureError:
    print ("BAD CLIENT SIGNATURE")
    print ("CLOSING CONNECTION")
    conn.send("exit".encode())
    s.shutdown(socket.SHUT_RDWR)
    s.close()
    os._exit(0)

#primanje javnog x25519 kljuca
while True:
    client_public_bytes = conn.recv(1024)
    if not client_public_bytes:
        sys.exit(0)
    break

#stvaranje zajednicke tajne
client_public_key2 = X25519PublicKey.from_public_bytes(client_public_bytes)
shared_key = server_private_key2.exchange(client_public_key2)

#slanje javnog x25519 kljuca
conn.send(server_public_bytes)

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