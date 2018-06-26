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
connection,IPclient = None,None

keys = dict()
cecuri = dict()
user = None

def startTCP_serv(IPvanzator,portVanzator):
	global s,IPclient
	s.bind((IPvanzator,portVanzator))
	s.listen(1)
	print(">> Astept clientul")
	(connection, address) = s.accept()
	IPclient = address
	return connection,address

def startTCP_client(IPbanca,portBanca):
	global s
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((IPbanca,portBanca))

def check_date(d):
	today = str(datetime.datetime.now().date())
	if d == today:
		return True
	else:
		return False

def receive_commit():
	global s,connection,IPclient,user

	print(">> Pornesc server TCP/IP")
	connection,IPclient = startTCP_serv(IPvanzator,portVanzator)

	print(">> Astept commit-ul")
	commit = bytes()
	while True:	
			data = connection.recv(100)
			commit += data 
			if b"exit" in data: break 

	signature = commit[:256]
	content = commit[256:-4]

	print(">> Am primit commitul si il desfac")

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
	date = date.decode("utf-8")
	n = commit[1566:1568]
	n = int(n.decode("utf-8"))

	cec_1leu = [cec_1_0]
	cec_5lei = [cec_5_0]
	cec_10lei = [cec_10_0]
	cecuri.update({"lenght":n,"1leu":cec_1leu,"5lei":cec_5lei,"10lei":cec_10lei})

	print(">> Verific semantura si commit-ul")
	try: #verific certificatul folosind cheia publica a lui B
		public_key_U.verify(signature,content,PSS(mgf=MGF1(hashes.SHA256()),salt_length=PSS.MAX_LENGTH),
					hashes.SHA256())
	except:
		print(">> Semnatura si certificatul nu se potrivesc!!!")
		return False
	else: #daca nu apare nici o eroare certificatul e valid
		print(">> Certificatul a fost autentificat si salvat.")
		if check_date(date):
			user = commit
			return True

	print(">> Salvez cheile publice B si U")
	keys.update({"public_key_B":public_key_B,"public_key_U":public_key_U})

def verify_collision(h,lista):
	if h in lista:
		return False
	else:
		return True

#functie recursiva care verifica hasul primit
def verify_hash(h,l):
	global cecuri

	digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
	digest.update(h)
	check = digest.finalize()

	if check == cecuri["1leu"][-1]:
		if verify_collision(h,cecuri["1leu"]):
			cecuri["1leu"].append(h)
			return 1
		else:
			return False
	elif check == cecuri["5lei"][-1]:
		if verify_collision(h,cecuri["5lei"]):
			cecuri["5lei"].append(h)
			return 5
		else:
			return False
	elif check == cecuri["10lei"][-1]:
		if verify_collision(h,cecuri["10lei"]):
			cecuri["10lei"].append(h)
			return 10
		else:
			return False
	elif l <= 1:
			return b"s-aoprit"
	else:
		x = verify_hash(check,l-1)
		if x == 1:
			cecuri["1leu"].append(h)
			return 1 
		elif x == 5:
			cecuri["5lei"].append(h)
			return 5
		elif x == 10:
			cecuri["10lei"].append(h)
			return 10
		elif x == False:
			return False
		
#pt campurile cu dimensiunea variabila le dau o dimesiune fixa
def add_bytes(byte,lenght):
	diferenta = lenght-len(byte)
	adaos = bytearray(diferenta)
	return byte+adaos

#fucntie care primeste hasul si il verifica folosint verify_hash
def receive_payment():
	global s,connection,IPclient

	h = bytes()
	h = connection.recv(32)
	if b"close" in h:
		return False

	l = cecuri["lenght"] - min(len(cecuri["1leu"]),len(cecuri["5lei"]),len(cecuri["10lei"]))
	
	verify_hash(h,l)

	return True


def printeaza_banii():
	global cecuri
	for key,item in cecuri.items():
		print(key)
		print(item)
	suma = len(cecuri["1leu"])-1 + 5*(len(cecuri["5lei"])-1)+ 10*(len(cecuri["10lei"])-1)
	print(">> Avem in de primit in total "+str(suma)+" lei")
	

#ma conectez la Banca pt rascumparare
def get_payed():
	global user,cecuri
	print(">> Incercam sa ne conectam la Banca")
	startTCP_client(IPbanca,portBanca)
	print(">> Ne-am conectat")
	l1 = add_bytes(str(len(cecuri["1leu"])-1).encode("utf-8"),3)
	l5 = add_bytes(str(len(cecuri["5lei"])-1).encode("utf-8"),3)
	l10 = add_bytes(str(len(cecuri["10lei"])-1).encode("utf-8"),3)
	data = user + cecuri["1leu"][-1] + cecuri["5lei"][-1] + cecuri["10lei"][-1] + l1+l5+l10
	print(">> Trimit commit-ul is hashurile")
	s.send(data)	
	s.close()


if receive_commit():
	check = True
	index = 1
	while check:
		check = receive_payment()
		index +=1
		s.close()
	print(">> Am inchis conexiunea cu Banca")
	printeaza_banii()
	get_payed()
	time.sleep(2)
	get_payed()
	