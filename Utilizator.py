from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key,PublicFormat,Encoding,ParameterFormat
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PSS,MGF1
import os
import socket,time
import pickle
import datetime

IPbanca = "127.0.0.1"
IPvanzator = "127.0.0.1"
portBanca = 1242
portVanzator = 1239

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

keys = dict()
my_info = dict()
cecuri = dict()

def startTCP_client(IPbanca,portBanca):
	global s
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((IPbanca,portBanca))

def DHexchange():
	global s

	parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())
	client_private_key = parameters.generate_private_key()
	client_public_key = client_private_key.public_key()
	serial_parameters = parameters.parameter_bytes(Encoding.PEM,ParameterFormat.PKCS3)
	serial_client_public_key = client_public_key.public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)

	s.send(serial_parameters)

	serial_serv_public_key = s.recv(1024)

	s.send(serial_client_public_key)
	
	serv_public_key = load_pem_public_key(serial_serv_public_key, backend=default_backend())
	shared_key = client_private_key.exchange(serv_public_key)

	key = HKDF(algorithm=hashes.SHA256(),length=32,salt=None, info=b'handshake data', 
		backend=default_backend()).derive(shared_key)
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

def certificate_exchange():
	global s,keys,my_info

	print(">> Ma conextex la banca.")
	#ma conectez la serverul TCP/IP
	startTCP_client(IPbanca,portBanca)

	print(">> Fac schimbul HD.")
	#fac schimbul DH si salvez cheia master DH si cheia pt encriptia simetrica
	DH,key = DHexchange()

	print(">> Generez cheia privata si publica.")
	#generez cheia purivata si cheia publica RSA
	private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048,
				backend=default_backend())
	public_key = private_key.public_key()

	#le salvez in dictionarul global keys
	keys.update({"private_key":private_key, "public_key":public_key})

	#serializez cheia publica
	serial_public_key = public_key.public_bytes(encoding=Encoding.PEM,
		format=PublicFormat.SubjectPublicKeyInfo)

	#generez IV-ul pt ecriptia simetrica 
	iv = generate_IV(DH,16)

	cont_bancar = b"167 123 123 123 123"
	nume = b"Anon Anonimus"

	inf_personale = serial_public_key + cont_bancar + nume

	#criptez cheia publica si informatiile personale
	criptotext = criptare_simetrica_AES(inf_personale,key,iv)

	print(">> Trimit inf personale pe canalul privat.")
	#trimit cheia si informatiile personale pt generarea certificatului
	s.send(criptotext)

	print(">> Primesc certificatul.")
	#primesc certificatul semnat
	criptotext= bytes()
	while True:	
		data = s.recv(100)
		criptotext += data 
		if not data: break 

	#desfac certificatul in semnatura, cheia lui B publica si restul informatiilor
	signature = criptotext[:256]
	IP = criptotext[256:265]
	public_key_B = criptotext[265:716] #451 dimensiunea cheii publice serializate
	#deserializez cheia lui B publica pt a verifica semnatura
	public_key_B = serialization.load_pem_public_key(public_key_B,backend=default_backend())
	public_key_U = criptotext[716:1167]
	info = criptotext[1167:]

	keys.update({"public_key_B":public_key_B})
	my_info.update({"certificat":criptotext,"numeral":1000})

	#compun certificatul fara semnatura
	certificat = criptotext[256:]

	print(">> Verific semnatura certificatului.")
	try: #verific certificatul folosind cheia publica a lui B
		public_key_B.verify(signature,certificat,PSS(mgf=MGF1(hashes.SHA256()),salt_length=PSS.MAX_LENGTH),
					hashes.SHA256())
	except:
		print(">> Semnatura si certificatul nu se potrivesc")
	else: #daca nu apare nici o eroare certificatul e valid
		print(">> Certificatul a fost autentificat si salvat.")

	s.close()

def generate_cec(n):
	cec = list()
	cec.append(os.urandom(32))
	for i in range(1,n):
		digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
		digest.update(cec[i-1])
		cec.append(bytes(digest.finalize()))
	return list(reversed(cec))

def compune_commit(cec_1_0,cec_5_0,cec_10_0,n):
	global my_info,keys
	identitate = b"netflix.com"
	identitate = add_bytes(identitate,32)
	date = str(datetime.datetime.now().date()).encode("utf-8")
	lenght = str(n).encode("utf-8")
	commit = my_info.get("certificat")+cec_1_0+cec_5_0+cec_10_0+identitate+date+lenght
	signature = keys["private_key"].sign(commit,PSS(mgf=MGF1(hashes.SHA256()),salt_length=PSS.MAX_LENGTH),hashes.SHA256()) 
	return signature+commit #256biti semnatura

#stabilesc conexiune cu V si ii trimit commit-ul semnat
def trimite_commit():
	global s
	n = 99
	cec_1leu = generate_cec(n)
	cec_5lei = generate_cec(n)
	cec_10lei = generate_cec(n)

	digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
	digest.update(cec_5lei[6])
	if digest.finalize() == cec_1leu[0]:
		print (True)
	else:
		print(False)

	cecuri.update({"lenght":n,"1leu":cec_1leu,"index1leu":0,"5lei":cec_5lei,"index5lei":0,"10lei":cec_10lei,"index10lei":0})

	commit = compune_commit(bytes(cec_1leu[0]),bytes(cec_5lei[0]),bytes(cec_10lei[0]),n)

	print(">> Ma conectez la vanzator.")
	startTCP_client(IPvanzator,portVanzator)
	print(">> Trimit commit-ul.")
	s.send(commit)
	s.send(b"exit")
	time.sleep(1)

def pay_1leu():
	global s
	cecuri["index1leu"]+=1
	if cecuri["index1leu"]<=99:
		s.send(cecuri["1leu"][cecuri["index1leu"]])
	else:
		print(">> Fonduri insuficiente!")

def pay_5lei():
	global s
	cecuri["index5lei"]+=1
	if cecuri["index5lei"]<=99:
		s.send(cecuri["5lei"][cecuri["index5lei"]])
	else:
		print(">> Fonduri insuficiente!")

def pay_10lei():
	global s
	cecuri["index10lei"]+=1
	if cecuri["index10lei"]<=99:
		s.send(cecuri["10lei"][cecuri["index10lei"]])
	else:
		print(">> Fonduri insuficiente!")

def pay_n_10lei(n):
	global s
	index = cecuri["index10lei"] + n 
	if index <= 99:
		s.send(cecuri["10lei"][index])
		cecuri["index10lei"] = index
	else:
		print("Fonuri insuficiente")

def pay_n_5lei(n):
	global s
	index = cecuri["index5lei"] + n 
	if index <= 99:
		s.send(cecuri["5lei"][index])
		cecuri["index5lei"] = index
	else:
		print("Fonuri insuficiente")

def pay_n_1leu(n):
	global s
	index = cecuri["index1leu"] + n 
	if index <= 99:
		s.send(cecuri["1leu"][index])
		cecuri["index1leu"] = index
	else:
		print("Fonuri insuficiente")


#stabilesc conexiunea privata cu clientul si salvez certificatul primit
certificate_exchange()

print(">> Avem urmatoarele chei:")
for key,value in keys.items():
	print(key + ":")
	print(value)

trimite_commit()

print(">> Incep sa platesc.")

pay_5lei()
pay_1leu()
pay_n_10lei(2)
pay_n_5lei(3)

#s.send(cecuri["5lei"][2])

print(">> Inchid conexiunea cu vanzatorul.")
s.send(b"closeconnection")