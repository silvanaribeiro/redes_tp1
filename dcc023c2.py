#Parametros do Cliente : Enedereco de Ip do servidor, porta do servidor, string texto, inteiro chave

import socket
import struct
import sys, getopt
import base64

class Quadro:
	sync = None
	length = None
	chksum = None
	ID = None
	flags = None
	dados = None

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

if __name__ == "__main__":
	main(sys.argv[1:])
