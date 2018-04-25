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
		msg = str(self.sync) + str(self.sync) + str(self.length) + str(self.chksum)
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


def createFrames(input):
	frame_list = []
	new_frame = True
	ID = 1
	sync = 3703579586
	length = 0
	data = ""
	flags = 0
	with open(input) as f:
		while True:
			if new_frame:
				data = ""
				ID = not ID
				new_frame = False

			c = f.read(1)
			data += c.strip()
			length += 1
			if len(data) == 128:
				frame = Frame(sync, length, 0, ID, flags, data)
				frame.calc_chksum()
				frame_list.append(frame)
				new_frame = True
				length = 0

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
    s = 0
    for i in range(0, len(msg) - 1, 2):
        w =(msg[i])+((msg[i+1])<<8)
        s = carry_around_add(s, w)
    return~s &0xffff

def splitTwoByTwo(val):
	args = [iter(val)] * 2
	return [''.join(k) for k in zip_longest(*args)]

def startClient(IP, PORT, INPUT, OUTPUT):
	print ("Iniciando o envio de frames")
	tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # criando socket)
	tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 15)
	tcp.settimeout(1) # timeout em segundos
	# nao funciona no mac hihihihihi
	# tcp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, 15)

	#creating frames
	frames = createFrames(INPUT)
	print (len(frames))
	# for frame in frames:
	# 	print(frame.sync)
	# 	print(frame.length)
	# 	print(frame.chksum)
	# 	print(frame.ID)
	# 	print(frame.flags)
	# 	print(frame.data)
	# 	print('--------')

	dest = (str(IP), int(PORT))
	tcp.connect(dest) # Conectando
	s = struct.Struct('>I')


	count = 0
	next = True
	#enviando a quantidade de quadros
	tcp.send(s.pack(int(len(frames))))

	# while(next and count < len(frames)):
	while(next and count < len(frames)):
		sendFrameClient(tcp, frames[count])
		# next = False

		sync = 3703579586
		# Recebe o pacote de ack
		try:
			s = struct.Struct('>I')
			texto = s.unpack(tcp.recv(4))[0]
			texto2 = s.unpack(tcp.recv(4))[0]
			if sync == texto and sync == texto2:
				length = decode16(tcp.recv(2))
				chksum = decode16(tcp.recv(2))
				ID = decode16(con.recv(1))
				flags = tcp.recv(1)
				dados = decode16(con.recv(int(length)))
				frame = Frame(sync, length, chksum, ID, flags, dados)
				msg = str(sync) + str(sync) + str(length) + str(0000)
				msg += str(self.ID) + str(self.flags) + str(self.data)
				result_check = checksum(msg)
				# se receber o ack corretamente, envia o proximo frame
				if result_check == chksum and length == 0 and flags == 0x80 and ID == frames[count].ID :
					# next = True
					count+=count
		except socket.timeout:
			print ("Reenviando frame...")

	tcp.close()

def sendFrameClient(tcp, frame):
	s = struct.Struct('>I')

	tcp.send(s.pack(int(frame.sync)))
	tcp.send(s.pack(int(frame.sync)))
	tcp.send(encode16(str(frame.length)))
	tcp.send(encode16(str(frame.chksum)))
	tcp.send(encode16(str(frame.ID)))
	if frame.ID:
		ID = 1
	else:
		ID = 0
	tcp.send(encode16(str(ID)))
	tcp.send(encode16(str(frame.flags)))
	tcp.send(encode16(frame.data))

def sendFrameServer(con, frame):
	s = struct.Struct('>I')
	tcp.send(s.pack(int(frame.sync)))
	tcp.send(s.pack(int(frame.sync)))
	con.send(encode16(frame.length))
	con.send(encode16(frame.chksum))
	con.send(frame.flags)
	con.send(encode16(frame.data))



def startServer(PORT, INPUT, OUTPUT):
	tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 15)

	orig = ('', int(PORT))
	tcp.bind(orig)
	tcp.listen(5)
	while 1:
		con, client = tcp.accept() # aceitando a conexao
		t=threading.Thread(target=handler, args=(con, client, OUTPUT))
		t.start() # iniciando nova thread que recebe dados do cliente
	tcp.close()


def handler(con, client, OUTPUT):
	s = struct.Struct('>I')
	qtd_frames = s.unpack(con.recv(4))[0]
	frames = []
	oldID = 1
	countFrames = 0
	while countFrames < qtd_frames:
		s = struct.Struct('>I')
		sync = 3703579586
		texto = s.unpack(con.recv(4))[0]
		texto2 = s.unpack(con.recv(4))[0]
		if sync == texto and sync == texto2:
			length = decode16(con.recv(2))
			chksum = decode16(con.recv(2))
			ID = decode16(con.recv(1))
			flags = decode16(con.recv(1))
			dados = decode16(con.recv(int(length)))
			frame = Frame(sync, length, chksum, ID, flags, dados)
			msg = str(sync) + str(length) + str(0000)
			msg += str(self.ID) + str(self.flags) + str(self.data)
			result_check = checksum(msg)
			if result_check == chksum and ID != oldID:
				frames.append(frame)
				oldID = ID
				frame = Frame(sync, 0, 0, ID, 0x80, '')
				frame.calc_chksum()
				countFrames += countFrames
				sendFrameServer(con, frame)
		con.close()
	writeFile(OUTPUT, frames)

def writeFile(output, frames):
	file = open(output,"w")
	for frames in frame:
		file.write(frame.data)
	file.close()

if __name__ == "__main__":
	main(sys.argv[1:])
