from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.serialization import load_pem_parameters,PublicFormat,Encoding,ParameterFormat
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PSS,MGF1
import os
import socket,time
import datetime

IPbanca = "127.0.0.1"
IPvanzator = "127.0.0.1"
IPclient = list()
portBanca = 1242
portVanzator = 1239
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def startTCP_serv(IPbanca,portBanca):
	global s,IPclient
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind((IPbanca,portBanca))
	print(">> Astept clientul.")
	s.listen(1)
	(connection, address) = s.accept()
	IPclient.append(address)
	return connection,address

def DHexchange(connection):

	serial_parameters = connection.recv(1024) #primeste obiectul parametrii serializat de unde genereaa cheia publica si privata DH

	parameters = serialization.load_pem_parameters(serial_parameters, backend=default_backend())#dezerializez obiectul parametrii
	serv_private_key = parameters.generate_private_key() #generaz cheia privata DH
	serv_public_key = serv_private_key.public_key() #generez cheia publica DH
	serial_serv_public_key = serv_public_key.public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)#serializez cheia publica
	
	connection.send(serial_serv_public_key) #trimit cheia publica
	
	serial_client_public_key = connection.recv(1024) #primesc cheia publica client serializata
	
	client_public_key = serialization.load_pem_public_key(serial_client_public_key, backend=default_backend()) #deserializez cheiaa
	shared_key = serv_private_key.exchange(client_public_key) #compun cheia comuna DH
	
	key = HKDF(algorithm=hashes.SHA256(),length=32,salt=None, info=b'handshake data', 
		backend=default_backend()).derive(shared_key) #generezo o cheie noua comuna din cheia DH
	return shared_key,key

def criptare_simetrica_AES(mesaj,key,iv):
	data = bytes()
	for i in range(0, len(mesaj), 16):
		bucata = mesaj[i:i+16]
		if(len(bucata)<16):
			padder = padding.PKCS7(128).padder()
			padded_data = padder.update(mesaj)
			bucata = padder.finalize()

		cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
		encryptor = cipher.encryptor()
		bucata = encryptor.update(bucata) + encryptor.finalize()

		data += bucata
	return data

def decriptare_simetrica_AES(criptotext,key,iv):
	data = bytes()
	for i in range(0, len(criptotext), 16):
		bucata = criptotext[i:i+16]
		cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
		decryptor = cipher.decryptor()
		mesaj = decryptor.update(bucata) + decryptor.finalize()

		if(bucata == criptotext[-16:]):
			unpadder = padding.PKCS7(128).unpadder()
			unpadder.update(mesaj)
			mesaj = unpadder.finalize()	

		data += mesaj
	return data

def generate_IV(derived_key,lenght):
	IV = HKDF(
    	algorithm=hashes.SHA512(),
    	length=32,
    	salt=None,
    	info=b'handshake data',
    	backend=default_backend()
		).derive(derived_key)
	return IV[:lenght]

def add_bytes(byte,lenght):
	diferenta = lenght-len(byte)
	adaos = bytearray(diferenta)
	return byte+adaos

def make_certificate(IP,public_key_B,public_key_U,info):
	certificat = IP[0].encode('utf-8') + public_key_B + public_key_U + info.encode('utf-8')
	return certificat


keys = dict()
user_info = dict()

def certificate_exchange():
	global keys,user_info

	print(">> Pornesc serverul TCP/IP")
	#pornesc serverul TCP/IP
	(connection, address) = startTCP_serv(IPbanca,portBanca)
	print("Clinet:", IPclient[-1])

	print(">> Se face schimbul DH")
	#se face schimbul DH si salvez cheile DH si cea pt encriptia simetrica
	DH, key = DHexchange(connection)

	print(">> Generez cheia privata si publica")

	#generez cheia privata si publica RSA
	serv_private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048,
				backend=default_backend())
	serv_public_key = serv_private_key.public_key()

	#le salvez in dictionarul global keys
	keys.update({"serv_private_key":serv_private_key,"serv_public_key":serv_public_key})

	#serializez cheia publica pentru a o putea trimite
	serial_public_key = serv_public_key.public_bytes(encoding=Encoding.PEM,
		format=PublicFormat.SubjectPublicKeyInfo)

	#generez un IV pt encriptia simetrica
	iv = generate_IV(DH,16)

	#primesc informatiile personale de la U
	criptotext = bytes()
	while True:	
		data = connection.recv(1024)
		criptotext += data 
		break

	#le decriptez si salvez
	inf_personale = decriptare_simetrica_AES(criptotext,key,iv)

	############ Am terminat cu canalul privat U-B ################

	#desfac informatiile personale pt a compune certificatul
	serial_public_key_client = inf_personale[:451]
	cont_bancar = inf_personale[451:470]
	nume = inf_personale[470:]
	client_public_key =  serialization.load_pem_public_key(serial_public_key_client,backend=default_backend())
	info = "nimic"

	#salvez cheia publica a lui U
	keys.update({"public_key_U":client_public_key})

	print(">> Compun certificatul.")
	#compun certificatul
	certificat = make_certificate(IPclient[-1],serial_public_key,serial_public_key_client,info)

	#compun semnatura pe certificat
	signature = serv_private_key.sign(certificat,PSS(mgf=MGF1(hashes.SHA256()),salt_length=PSS.MAX_LENGTH),hashes.SHA256())

	#adaug semnatura la certificat
	certificat = signature + certificat

	#salvez datele personale ale userului intr-un dictionar
	user_info.update({"nume":nume.decode("UTF-8"),"cont_bancar":cont_bancar.decode("UTF-8"),"certificat":certificat,"numeral":1000,"info":info})

	print(">> Trimit certificatul.")
	#trimit certificatul lui U
	connection.send(certificat)

	#certificatul a fost trimis inchid conexiunea
	connection.close()

	print(">> Certificatul a fost trimis si salvat. \n>> Am inchis conexiunea cu clientul.")

def take_back_bytes(l):
	i = l.decode("utf-8")
	i = i.replace('\x00','')
	i = int(i) 
	return i

def verifica_hash(h,c,l):
	check = h
	his = list()
	for i in range(0,l):
		digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
		digest.update(check)
		check = digest.finalize()
		his.append(check)
	if check == c:
		return his.copy()
	else:
		return False

history = list()

def pay_vendor():
	global history
	print(">> Pornim serverul TCP/IP")
	connection,address = startTCP_serv(IPbanca,portBanca)
	print(address)
	criptotext = b""
	while True:	
		data = connection.recv(1024)
		criptotext += data 
		if not data: break	

	print(">> Am primit commitul si hasurile")
	if not criptotext:
		return False
	commit = criptotext[:1572]
	c1 = criptotext[1572:1604]
	c5 = criptotext[1604:1636]
	c10 = criptotext[1636:1668]
	l1 = criptotext[1668:1671]
	l1 = take_back_bytes(l1)
	l5 = criptotext[1671:1674]
	l5 = take_back_bytes(l5)
	l10 = criptotext[1674:1677]
	l10 = take_back_bytes(l10)

	signature = commit[:256]
	content = commit[256:-4]

	IP = content[256:265]
	public_key_B = content[265:716] #451 dimensiunea cheii publice serializate
	#deserializez cheia lui B publica pt a verifica semnatura
	public_key_B = serialization.load_pem_public_key(public_key_B,backend=default_backend())
	public_key_U = content[716:1167]
	public_key_U = serialization.load_pem_public_key(public_key_U,backend=default_backend())

	cec_1_0 = commit[1428:1460]
	cec_5_0 = commit[1460:1492]
	cec_10_0 = commit[1492:1524]
	indentitate = commit[1524:1556]
	date = commit[1556:1566]
	n = commit[1566:1568]
	n = int(n.decode("utf-8"))

	try: #verific certificatul folosind cheia publica a lui B
		public_key_U.verify(signature,content,PSS(mgf=MGF1(hashes.SHA256()),salt_length=PSS.MAX_LENGTH),
				hashes.SHA256())
	except:
		print(">> Semnatura si certificatul nu se potrivesc!!!")
		return False
	else: #daca nu apare nici o eroare certificatul e valid
		print(">> Certificatul a fost autentificat si salvat.")
		check1 = verifica_hash(c1,cec_1_0,l1)
		check5 = verifica_hash(c5,cec_5_0,l5)
		check10 = verifica_hash(c10,cec_10_0,l10)
		if check1 != False and check5 != False and check10 != False:
			print(">> Hasurile sunt bune.")
			if check1 not in history and check5 not in history and check10 not in history:
				history.append(check1)
				history.append(check5)
				history.append(check10)
				print(">> Tanzactia a fost aprobata si salvata in istoric.")
				suma = len(history[0]) + 5*len(history[1])+ 10*len(history[2])
				print(">> Vendorul primeste " + str(suma)+" lei.")
				return True
			else: 
				print(">> Tranzactia nu a fost aprobata.")
		else: 
			print(">> Tranzactia nu a fost aprobata.")

#stabilesc conexiunea privata cu clientul si ii trimit certificatul semnat
certificate_exchange()

print(">> Avem urmatoarele chei:")
for key,value in keys.items():
	print("   " +key + ":")
	print(value)

while pay_vendor():
	pass
