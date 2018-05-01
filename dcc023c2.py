import socket
from socket import AF_INET, SOCK_DGRAM
import struct
import sys, getopt
import base64
from itertools import zip_longest
import binascii

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

	def print(self):
		print ("Sync: ", self.sync)
		print ("length: ", str(self.length))
		print ("chksum: ", str(self.chksum))
		print ("ID: ", str(self.ID))
		print ("flags: ", str(self.flags))
		print ("data: ", self.data)

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
			data += c.decode('ascii' , 'ignore')
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
	print("	--- 	RECEBEU FRAME ---")
	sync2 =  int(con.recv(8).decode('ascii'), 16)
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
	tcp.settimeout(1) # timeout em segundos
	s = struct.Struct('>I')
	writeFile(OUTPUT)
	#criando os frames
	frames = createFrames(INPUT)
	dest = (str(IP), int(PORT))
	tcp.connect(dest) # Conectando

	print("	--- 	ENVIA FRAME INICIAL	---")
	count = 0
	oldID = 1
	sendFrame(tcp, frames[count])
	enviado = False
	while not enviado:
		try:
			frame, dadosNonDecoded = receive_frame(tcp)
			print ("Frame: ", frame.to_str())
			frame.print()
			if frame.flags == flagACK:
				chksum = frame.chksum
				result_check = frame.calc_chksum(dadosNonDecoded)
				# se receber o ack corretamente, envia o proximo frame
				if result_check == chksum and frame.length == 0 and frame.flags == flagACK and frame.ID == frames[count].ID :
					print("RECEBEU ACK FRAME INICIAL", count)
					count+=1
					print("	--- 	INICIA CONVERSA	---")
					start_conversation(OUTPUT, tcp, frames, count, oldID)
					enviado = True
		except socket.timeout as e:
			print ("Timeout.Reenviando frame")
	socket.close()

def start_conversation(OUTPUT, tcp, frames, count, oldID):
	frames_arquivo = []
	tcp.settimeout(1) # timeout em segundos
	loop = True
	while loop:
			# envia seus proprios quadros
			if count < len(frames):
				print("	--- 	ENVIA FRAME	---")
				sendFrame(tcp, frames[count])

			try:
				frame, dadosNonDecoded = receive_frame(tcp)
				print ("Frame: ", frame.to_str())
				frame.print()
				print ("Flag frame: ", frame.flags)
				if frame.flags == flagACK:
					chksum = frame.chksum
					result_check = frame.calc_chksum(dadosNonDecoded)
					# se receber o ack corretamente, envia o proximo frame
					if result_check == chksum and frame.length == 0 and frame.flags == flagACK and frame.ID == frames[count].ID :
						print("RECEBEU ACK DO FRAME ", count)
						count+=1

				else:
					new_frame = Frame(frame.sync, frame.length, 0, frame.ID, frame.flags, frame.data)
					new_frame.calc_chksum()
					if frame.chksum == new_frame.chksum and frame.ID != oldID:
						writeFile(OUTPUT, frame)
						oldID = new_frame.ID
						frames_arquivo.append(frame)
						frame_ack = Frame(sync, 0, 0, frame.ID, flagACK, '')
						frame_ack.calc_chksum()
						# writeFile(OUTPUT, frame_ack)
						# Enviar ack
						print("	--- 	ENVIA ACK	---")
						sendFrame(tcp, frame_ack)
			except socket.timeout as e:
				print ("Timeout")

	tcp.close()

def rec_data(con, length):

	passo = 400
	dado = ''
	resto = length*2
	while resto != 0:
		if resto < passo:
			dado += con.recv(resto)
			resto = 0
		else:
			dado += con.recv(passo)
			resto -= passo
	return decodeMessage(dado), dado


def sendFrame(tcp, frame):
	print("Frame: ", frame.to_str())
	frame.print()

	tcp.send(padhexa(hex(frame.sync), 8)[2:].encode('ascii'))
	tcp.send(padhexa(hex(frame.sync), 8)[2:].encode('ascii'))
	tcp.send(padhexa(hex(frame.length), 4)[2:].encode('ascii'))
	tcp.send(padhexa(hex(frame.chksum), 4)[2:].encode('ascii'))
	tcp.send(padhexa(hex(int(frame.ID)), 2)[2:].encode('ascii'))
	tcp.send(padhexa(hex(frame.flags), 2)[2:].encode('ascii'))
	# print("DADO", encodeMessage(str(frame.data)))
	tcp.send(encodeMessage(str(frame.data)))
	print ("Frame enviado com sucesso")

def startServer(PORT, INPUT, OUTPUT):
	# print ("INICIANDO SERVIDOR")
	tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 15)
	writeFile(OUTPUT)
	frames = createFrames(INPUT)
	orig = ('', int(PORT))
	oldID = 1
	tcp.bind(orig)
	tcp.listen(5)
	loop = True
	con, client = tcp.accept() # aceitando a conexao
	while loop:
		try:
			frame, dadosNonDecoded = receive_frame(con)
			print ("Frame: ", frame.to_str())
			frame.print()
			new_frame = Frame(frame.sync, frame.length, 0, frame.ID, frame.flags, frame.data)
			new_frame.calc_chksum()
			print ("chksum antigo: ", frame.chksum )
			print ("chksum novo: ", new_frame.chksum )
			if frame.chksum == new_frame.chksum and frame.ID != oldID:
				writeFile(OUTPUT, frame)
				oldID = new_frame.ID
				frame_ack = Frame(sync, 0, 0, frame.ID, flagACK, '')
				frame_ack.calc_chksum()
				# Enviar ack
				print("	--- 	ENVIA PRIMEIRO ACK	---")
				sendFrame(con, frame_ack)
			print("	--- 	INICIA CONVERSA	---")
			start_conversation(OUTPUT, con, frames, 0, oldID)
			loop = False
		except Exception as e:
			print("Unhandled exception", e)
			loop = False
	tcp.close()

def writeFile(output, frame = None):
	if frame:
		print ("Gravando no arquivo")
		file = open(output,"a")
		file.write(frame.data)
	else:
		print ("Limpeza inicial do arquivo")
		file = open(output,"w")
	file.close()

if __name__ == "__main__":
	main(sys.argv[1:])
