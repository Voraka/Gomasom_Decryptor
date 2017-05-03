#----------------------------------------
#Author		:	Voraka
#Email		:	voraka@163.com
#Date		:	5/2/2017
#Details	:	https://www.bleepingcomputer.com/news/security/gomasom-crypt-ransomware-decrypted/
#----------------------------------------

import os
import sys
import time
import binascii
import hashlib
import ctypes
from Crypto.Cipher import DES3



class Gomasom():
	def __init__(self):
		self.seedl = 0
		self.seedh = 0
		self.seed0 = 0
		self.KeyMD5 = None
		self.SN = ""
		self.IV = ""
		self.CryptedFiles = []
		
		
	def get_SN(self):
		sn = ""
		if  not os.path.exists(r"C:\Crypted.txt"):
			print 'SN file not found!  '
		lines = open(r"C:\Crypted.txt", "rb").readlines()
		for line in lines:
			if "S/N" in line:
				sn = line.split(' ')[1].replace('\r', '').replace('\n', '')			
				self.SN = sn
				seed0 = int(sn[-1:])	#skip \n \r
				self.seed0 = seed0
		
	def rand(self):
		# call QueryPerformanceCounter to get seed(seedl, seedh)
		self.seedl = 0x6D80583A
		self.seedh = 0x5BA		

	def srand(self, num):	
		self.seedl = self.seedl *134775813+1 & 0xffffffff
		self.seedh = eval(hex(num * self.seedl)[:-9])
		

	def generate_SN(self):
		sn = ""
		map = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890!@#$%^&*()_+|\=-<>/?"		
		self.srand(0x9)		
		self.seed0 = self.seedh	
		for i in range(0xe):			
			self.srand(0x4f)		
			sn +=map[self.seedh]		
		if 0<self.seed0<10:
			last_keychar =str(self.seed0 % 10)		
			sn +=last_keychar	
		self.SN = sn
		

	def get_IV(self):
		ivs = 	[
				"\xA9\xCB\x00\x7C\xAA\x9B\xDB\xB6",
				"\x43\x92\x2F\xD2\x98\x80\xAB\x09",
				"\x9F\xB9\xE1\xC4\x68\xB3\x3B\xFF",
				"\x0D\x6A\x0C\xE3\xA5\x11\xC6\x75",
				"\x3C\x80\xE5\x44\xFD\xB1\x26\x76",
				"\x2D\x0E\xFE\x20\x2F\xD4\x9B\x66",
				"\xFB\x9C\x38\xA0\x73\xC7\x10\x57",
				"\xDA\x4A\xDC\xB5\xF5\x18\xF9\x30",
				"\xEC\x01\x55\x65\xF0\x13\xAE\x28",
				"\xD4\xA7\xBC\x16\x6B\xE2\xCB\x7B"
			]
				
		iv = ivs[self.seed0]
		self.IV = iv
		print "\tIV : "+iv.encode('hex')
		
	def generate_KeyMD5(self):		
		keys = 	[
				"\x9D\x0E\xE1\x0E\xAB\xDA\x3C\x46\x6D\x8E\xC1\xBD\x65\x5D\x59\x44\xF5\x89\xD3\x53\x30\x6A\xBF\x8E",
				"\x4C\x49\xB4\xE3\x9E\xEE\x35\x18\x43\xE9\x05\x30\x6B\xAD\xA7\xC5\x0B\x96\x86\x9C\x39\x23\x31\xCF",
				"\x39\x38\x42\xC3\x78\xF1\xAA\x23\x24\x5D\x1C\x2A\xCA\x9D\xDD\x2A\x71\xE7\x4C\xCE\x88\xBC\x3F\xC0",
				"\x1F\x44\x59\xBA\x76\xAE\xC1\x2A\xAA\xF6\xF7\x89\xA8\x2A\x13\x0F\x2B\x2A\x5B\xE4\x6B\xD9\x1D\x62",
				"\x1B\x4D\x0E\xAB\x24\x99\x16\x3E\xC8\x3D\x0E\x47\x32\xE4\x6A\xFC\xF6\xD9\x11\x0E\x05\x45\x2A\xC0",
				"\xD0\x90\x05\x77\xA3\x1E\xB2\x0C\xA4\x2A\xA9\xA7\xD7\xA0\x34\xD0\x31\xE1\x4A\xA2\xF5\x28\x12\x0C",
				"\xDF\xC0\x16\x2A\xDC\x61\xC6\x24\x33\x13\xDD\x75\x9A\xE6\xBF\x44\x4C\xD2\x5A\xC9\xDF\xD5\x68\x08",
				"\xBF\x2B\x2A\x80\x4D\x70\x8B\xF7\xE6\x2A\xDA\x96\xF8\x7C\xD8\xDD\x85\x04\x77\xE1\x5F\x0B\x73\xCB",
				"\x6A\xDF\x5A\x12\x4B\x0B\x8C\x07\x2E\x07\x5E\x65\x34\xF3\x9F\xD3\x41\x39\xED\x2D\x4A\xCF\xA5\x71",
				"\xBF\x96\xAF\x5B\xBE\x59\x3D\x86\x41\xD8\xC4\x87\x17\xBD\x23\x6D\xAB\x95\x2B\x57\x9A\xF1\x2A\xCF"
			]
		key = keys[(self.seed0)]
		print "\tKey: "+key.encode('hex')
		md5 = hashlib.md5()
		md5.update(key)
		key_md5 = md5.digest()
		self.KeyMD5 = key_md5
		print "\tMD5: "+key_md5.encode('hex')

	def get_crypted_files(self):
		crypted_files = []
		disks = []
		lpBuffer = ctypes.create_string_buffer(10)  
		ctypes.windll.kernel32.GetLogicalDriveStringsA(ctypes.sizeof(lpBuffer), lpBuffer)  
		vol = lpBuffer.raw.split('\x00')  
		for v in vol:  
			if v:  
				disks.append(v)
		for d in disks:			
			list_dirs = os.walk(d) 
			for root, dirs, files in list_dirs: 
				for d in dirs: 					
					filepath = os.path.join(root, d)      
					if filepath.endswith('crypt'):
						crypted_files.append(filepath)
				for f in files: 
					filepath = os.path.join(root, f) 
					if filepath.endswith('crypt'):
						crypted_files.append(filepath)
		for cf in crypted_files:
			print "\t"+cf
		self.CryptedFiles = crypted_files
			
	def decrypt_file(self, inpath):
		try:
			BS = DES3.block_size
			pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
			unpad = lambda s : s[0:-ord(s[-1])]
			
			if inpath.endswith('crypt'):
				enc_buffer = open(inpath, "rb").read()			
				cipher = DES3.new(self.KeyMD5, DES3.MODE_CBC, self.IV)
				if (len(enc_buffer)%8)!=0:
					enc_buffer = pad(enc_buffer)
				dec_buffer = cipher.decrypt(enc_buffer)
				with open(inpath.replace('.crypt', ''), 'wb')as f:
					f.write(dec_buffer)
					f.close()
				print '%s decryptd! :)\n' %inpath
				# os.remove(inpath)			
		except:
			pass
			
def main():
	gomasom = Gomasom()
	print '[+] Get the key info...'
	# gomasom.rand()
	# gomasom.generate_SN()
	gomasom.get_SN()
	print "\tS/N: "+gomasom.SN	
	gomasom.generate_KeyMD5()
	gomasom.get_IV()
	print '[+] Finding crypted files...'
	gomasom.get_crypted_files()
	print '[+] Decrypt these files...'
	if gomasom.CryptedFiles:
		for crypted_filepath in gomasom.CryptedFiles:			
			gomasom.decrypt_file(crypted_filepath)
	
if __name__=='__main__':
	main()