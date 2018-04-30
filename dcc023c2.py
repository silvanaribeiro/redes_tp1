import socket
import struct
import sys, getopt
import base64
from itertools import zip_longest
import binascii
import threading

# REFERENCES:
# https://www.rapidtables.com/convert/number/ascii-hex-bin-dec-converter.html
# https://www.mkyong.com/python/python-3-convert-string-to-bytes/

sync = 3703579586
flagACK = 128
flag = 0
class Frame:
	sync = None
	length = None
	chksum = None
	ID = None
	flags = None
	data = None

	def __init__(self, sync, length, chksum, ID, flags, data):
		self.sync = sync
		self.length = length
		self.chksum = chksum
		self.ID = ID
		self.flags = flags
		self.data = data

	def to_str(self, dadosNonDecoded=None):
		msg = padhexa(hex(self.sync), 8)[2:]
		msg += padhexa(hex(self.sync), 8)[2:]
		msg += padhexa(hex(self.length), 4)[2:]
		msg += padhexa(hex(self.chksum), 4)[2:]
		msg += padhexa(hex(int(self.ID)), 2)[2:]
		msg += padhexa(hex(self.flags), 2)[2:]
		if not dadosNonDecoded:
			msg += encodeMessage(str(self.data))
		else:
			msg += dadosNonDecoded
		return msg

	def calc_chksum(self, dadosNonDecoded=None):
		self.chksum = 0
		lista = splitTwoByTwo(self.to_str(dadosNonDecoded))
		lista_int = list()
		for f in lista:
			lista_int.append(int(f, 16))
		self.chksum = checksum(lista_int)
		return self.chksum

def main(argv):
	opts = None
	args = None
	PORT = None
	IP = None
	OUTPUT = None
	INPUT = None
	try:
		opts, args = getopt.getopt(argv, "s:c:")
	except getopt.GetoptError:
		print("dcc023c2.py -s <PORT> <INPUT> <OUTPUT>")
		print("dcc023c2.py -c <IP>:<PORT> <INPUT> <OUTPUT>")
	for opt, arg in opts:
		if opt == '-s':
			PORT = arg
		elif opt == '-c':
			IP, PORT = arg.split(':')

		INPUT = args[0]
		OUTPUT = args[1]
		if IP:
			startClient(IP, PORT, INPUT, OUTPUT)
		else:
			startServer(PORT, INPUT, OUTPUT)

def decode16(c):
	return base64.b16decode(c)

def encode16(c):
	return base64.b16encode(c.encode('ascii'))

def decodeMessage(msg):
	decoded = ''
	bytes = splitTwoByTwo(msg.upper())
	for byte in bytes:
		decoded += decode16(byte).decode('ascii')
	return decoded.replace("'", "")

def encodeMessage(msg):
	encoded = ''
	for c in msg:
		encoded += str(encode16(c))[1:]
	return encoded.replace("'", "")

def carry_around_add(a, b):
    c = a + b
    return(c &0xffff)+(c >>16)

def checksum(msg):
    s = 0
    for i in range(0, len(msg) - 1, 2):
        w =(msg[i]<<8)+((msg[i+1]))
        s = carry_around_add(s, w)
    return~s &0xffff

def splitTwoByTwo(val):
	args = [iter(val)] * 2
	return [''.join(k) for k in zip_longest(*args)]

def padhexa(s,qtd):
    return '0x' + s[2:].zfill(qtd)

def createFrames(input):
	frame_list = []
	new_frame = True
	ID = 1
	data = ""
	with open(input, "rb") as f:
		while True:
			if new_frame:
				data = ""
				ID = not ID
				new_frame = False

			c = f.read(1)
			data += c.decode('ascii', 'ignore')
			if len(data) == 128:
				frame = Frame(sync, len(data), 0, ID, flag, data)
				frame.calc_chksum()
				frame_list.append(frame)
				new_frame = True
			if not c:
				break
	if not new_frame:
		frame = Frame(sync, len(data), 0, ID, flag, data)
		frame.calc_chksum()
		frame_list.append(frame)

	return frame_list

def receive_frame(con):
	sync1 =  int(con.recv(8).decode('ascii'), 16)
	# print("Sync1", sync1)
	print("	--- 	RECEBEU FRAME ---")
	sync2 =  int(con.recv(8).decode('ascii'), 16)
	# print("sync2", sync2)
	if sync == sync1 and sync2 == sync2:
		length =  int(con.recv(4).decode('ascii'), 16)
		chksum =  int(con.recv(4).decode('ascii'), 16)
		ID =  int(con.recv(2).decode('ascii'), 16)
		flags =  int(con.recv(2).decode('ascii'), 16)
		dadosDecoded, dados = rec_data(con, length)
		frame = Frame(sync, length, chksum, ID, flags, dadosDecoded)
	return frame, dados

def startClient(IP, PORT, INPUT, OUTPUT):
	tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # criando socket
	tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 15)
	# tcp.settimeout(1) # timeout em segundos
	s = struct.Struct('>I')
	#criando os frames
	frames = createFrames(INPUT)
	dest = (str(IP), int(PORT))
	tcp.connect(dest) # Conectando

	print("	--- 	ENVIA FRAME INICIAL	---")
	sendFrame(tcp, frames[0])
	print("	--- 	INICIA CONVERSA	---")
	frame, dadosNonDecoded = receive_frame(tcp)
	enviado = False
	while not enviado:
		try:
			if frame.flags == flagACK:
				chksum = frame.chksum
				result_check = frame.calc_chksum(dadosNonDecoded)
				# se receber o ack corretamente, envia o proximo frame
				if result_check == chksum and frame.length == 0 and frame.flags == flagACK and frame.ID == frames[count].ID :
					count+=1
					print("RECEBEU ACK FRAME INICIAL", count)
					start_conversation(OUTPUT, tcp, frames, 1)
					enviado = True
		except:
			print ("Timeout.Reenviando frame")


def start_conversation(OUTPUT, socket, frames, count):
	oldID = 1
	frames_arquivo = []
	writeFile(OUTPUT)
	print ("FRAMES: ", len(frames))
	while True:
			# agora, volta a enviar seus proprios quadros
			if count < len(frames):
				print("	--- 	ENVIA FRAME	---")
				sendFrame(socket, frames[count])

			try:
				frame, dadosNonDecoded = receive_frame(socket)
				if frame.flags == flagACK:
					chksum = frame.chksum
					result_check = frame.calc_chksum(dadosNonDecoded)
					# se receber o ack corretamente, envia o proximo frame
					if result_check == chksum and frame.length == 0 and frame.flags == flagACK and frame.ID == frames[count].ID :
						count+=1
						print("RECEBEU ACK", count)
				else:
					new_frame = Frame(frame.sync, frame.length, 0, frame.ID, frame.flags, frame.data)
					new_frame.calc_chksum()
					print("Frame: ", frame.to_str())
					print('new frame.chksum :', new_frame.chksum)
					print('chksum recebido :', frame.chksum)
					if frame.chksum == new_frame.chksum and frame.ID != oldID:
						writeFile(OUTPUT, frame)
						oldID = new_frame.ID
						frames_arquivo.append(frame)
						frame_ack = Frame(sync, 0, 0, frame.ID, flagACK, '')
						frame_ack.calc_chksum()
						writeFile(OUTPUT, frame_ack)
						# Enviar ack
						print("	--- 	ENVIA ACK	---")
						sendFrame(socket, frame_ack)
			except:
				print ("Timeout.Reenviando frame")


def rec_data(con, length):

	passo = 400
	dado = ''
	resto = length*2
	while resto != 0:
		if resto < passo:
			dado += con.recv(resto).decode('ascii')
			resto = 0
		else:
			dado += con.recv(passo).decode('ascii')
			resto -= passo
	return decodeMessage(dado), dado


def sendFrame(tcp, frame):
	print("Frame: ", frame.to_str())

	tcp.send(padhexa(hex(frame.sync), 8)[2:].encode('ascii'))
	tcp.send(padhexa(hex(frame.sync), 8)[2:].encode('ascii'))
	tcp.send(padhexa(hex(frame.length), 4)[2:].encode('ascii'))
	tcp.send(padhexa(hex(frame.chksum), 4)[2:].encode('ascii'))
	tcp.send(padhexa(hex(int(frame.ID)), 2)[2:].encode('ascii'))
	tcp.send(padhexa(hex(frame.flags), 2)[2:].encode('ascii'))
	tcp.send(encodeMessage(str(frame.data)).encode('ascii'))
	print ("Frame enviado com sucesso")

def startServer(PORT, INPUT, OUTPUT):
	print ("INICIANDO SERVIDOR")
	tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 15)
	frames = createFrames(INPUT)
	orig = ('', int(PORT))
	tcp.bind(orig)
	tcp.listen(5)
	while 1:
		con, client = tcp.accept() # aceitando a conexao
		print("	--- 	INICIA CONVERSA	---")
		t=threading.Thread(target=start_conversation, args=(OUTPUT, con, frames, 0))
		t.start() # iniciando nova thread que recebe dados do cliente
	tcp.close()

def writeFile(output, frame = None):
	print ("Gravando no arquivo")
	if frame:
		file = open(output,"a")
		file.write(frame.data)
	else:
		file = open(output,"w")
	file.close()

if __name__ == "__main__":
	main(sys.argv[1:])
