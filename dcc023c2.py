#Parametros do Cliente : Enedereco de Ip do servidor, porta do servidor, string texto, inteiro chave

import socket 
import struct
import sys, getopt
import base64

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
		
		readFile(INPUT)
		
		print (IP, PORT, INPUT, OUTPUT)
		
		
def readFile(input):
	with open(input) as f:
		while True:
			c = f.read(1)
			if not c:
				print("End of file")
				break
			print("Read a character:",c, base64.b16encode(c.encode('ascii')))
	
if __name__ == "__main__":
	main(sys.argv[1:])
	
	