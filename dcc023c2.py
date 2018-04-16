#Parametros do Cliente : Enedereco de Ip do servidor, porta do servidor, string texto, inteiro chave

import socket 
import struct

def main(argv):
	HOST = None
	PORT = None
	texto = None
	chave = None
	
	try:
		opts, args = getopt.getopt(argv, "p:")
		print opts
		print args
	except getopt.GetoptError:
		print "dcc023c2.py -s <PORT> <INPUT> <OUTPUT>"
		print "dcc023c2.py -c <IP>:<PORT> <INPUT> <OUTPUT>"
	for opt, arg in opts:
		if opt == '-s':
			print arg
		elif opt == '-c':
			print arg
		
	
if __name__ == "__main__":
	main(sys.argv[1:])
	
	