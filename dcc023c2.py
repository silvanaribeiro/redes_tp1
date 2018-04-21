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

	def calc_chksum(self):
		msg = str(self.sync) + str(self.length) + str(self.chksum)
		msg += str(self.ID) + str(self.flags) + str(self.data)
		self.chksum = checksum(msg.encode())

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
		print (IP, PORT, INPUT, OUTPUT)
		if IP:
			startClient(IP, PORT, INPUT, OUTPUT)
		else:
			startServer(PORT, INPUT, OUTPUT)



def decodeMessage(msg):
	decoded = ''
	bytes = splitTwoByTwo(msg.upper())
	for byte in bytes:
		decoded += str(decode16(byte))
	return decoded


# def readFile(input):
# 	with open(input) as f:
# 		while True:
# 			c = f.read(1)
# 			if not c:
# 				print("End of file")
# 				break

def createFrames(input):
	frame_list = []
	new_frame = True
	ID = 0
	sync = "dcc023c2dcc023c2"
	length = 0
	data = ""
	with open(input) as f:
		while True:
			if new_frame:
				data = ""
				ID += 1
				new_frame = False

			c = f.read(1)
			data += c.strip()
			length += 1
			if sys.getsizeof(data) == 128:
				flags = 0
				# print ("DATA EM BYTES:", data.encode())
				frame = Frame(sync,length, 0, ID, flags, data)
				frame.calc_chksum()
				frame_list.append(frame)
				new_frame = True

			if not c:
				print("End of file")
				break
	if not new_frame:
		frame = Frame(sync,length, 0, ID, flags, data)
		frame.calc_chksum()
		frame_list.append(frame)

	return frame_list

def encode16(c):
	return base64.b16encode(c.encode('ascii'))

def decode16(c):
	return str(base64.b16decode(c.encode('utf-8')))

def carry_around_add(a, b):
    c = a + b
    return(c &0xffff)+(c >>16)

def checksum(msg):
    s =0
    for i in range(0, len(msg) - 1, 2):
        w =(msg[i])+((msg[i+1])<<8)
        s = carry_around_add(s, w)
    return~s &0xffff

def splitTwoByTwo(val):
	args = [iter(val)] * 2
	return [''.join(k) for k in zip_longest(*args)]

def startClient(IP, PORT, INPUT, OUTPUT):
	tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # criando socket)
	tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 15)
	# nao funciona no mac hihihihihi
	# tcp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, 15)

	#creating frames
	frames = createFrames(INPUT)
	print (len(frames))
	dest = (str(IP), int(PORT))
	tcp.connect(dest) # Conectando
	s = struct.Struct('>I')
	# TODO do this for all packages
	# TODO send package
	# for f in frames:


	# tcp.send().encode('ascii')) # Enviando texto ao servidor codificado em base16
	# TODO wait for response, resend if not ok
	# ack = tcp.recv().decode('ascii')    # Recebendo resposta do servidor
	tcp.close()


def startServer(PORT, INPUT, OUTPUT):
	tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 15)
	# nao funciona no mac hihihihihi
	# tcp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, 15)
	orig = ('', int(PORT))
	tcp.bind(orig)
	tcp.listen(5)
	while 1:
		con, client = tcp.accept() # aceitando a conexao

		t=threading.Thread(target=handler, args=(con, client))
		t.start() # iniciando nova thread que recebe dados do cliente
	tcp.close()


def handler(con, client):
	s = struct.Struct('>I')
	#TODO receive packages till its done
	#texto = con.recv().decode('ascii') # Recebe o pacote
	#TODO checksum
	#TODO send ack if checksum ok
	#con.send() # Envia ack
	con.close()


if __name__ == "__main__":
	main(sys.argv[1:])
