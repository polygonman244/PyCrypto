# Encryption and hashing using PyCrypto!
import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

# Declare encrypt function
def encrypt(key, filename):
	chunksize = 64*1024 	# Size of each chunk
	outputFile = "(encrypted)"+filename # File we specify to encrypt
	filesize = str(os.path.getsize(filename)).zfill(16) # Size of file
	IV = Random.new().read(16) # Our Initialization Vector 'IV' for padding
	
	"""Initialization vector: A number that can be used along with a
	secret key for our data encryption. This number is also known as
	a 'nonce'."""
	
	"""Padding: allows us to have our plaintext be smaller than the
	blocksize by filling in extra space inside the block."""
	
	# AES symmetric algorithm
	encryptor = AES.new(key, AES.MODE_CBC, IV)
	
	# Our file that we will encrypt
	with open(filename, 'rb') as infile: 
		# What the program will output once encryption is done
		with open(outputFile, 'wb') as outfile:
			outfile.write(filesize.encode('utf-8'))
			outfile.write(IV)
			
			while True:
				chunk = infile.read(chunksize)
				
				# Here we do our padding so that we dont get errors
				if len(chunk) == 0:
					break
				elif len(chunk) % 16 != 0:
					chunk += b' ' * (16 - (len(chunk) % 16))
				
				# Finish encryption 
				outfile.write(encryptor.encrypt(chunk))

# Declare decrypt function
# Here we just do the inverse of our encryption function
def decrypt(key, filename):
	chunksize = 64*1024
	# Strip first 11 characters from front of filename
	outputfile = filename[11:] 
	
	with open(filename, 'rb') as infile:
		filesize = int(infile.read(16))
		IV = infile.read(16)
		
		decryptor = AES.new(key, AES.MODE_CBC, IV)
		
		with open(outputfile, 'wb') as outfile:
			while True:
				chunk = infile.read(chunksize)
				
				if len(chunk) == 0:
					break
				
				outfile.write(decryptor.decrypt(chunk))
			
			# Get rid of residual padding left over from initial encryption		
			outfile.truncate(filesize) 

# Function for verifying our password through SHA-256
def getKey(password):
	hasher = SHA256.new(password.encode('utf-8'))
	return hasher.digest()

# Main function for the program
def Main():
	# Have user encrypt or decrypt our file
	'''Note: can only encrypt or decrypt in AES-256'''
	init = input("Press 'Enter' key to start(or 'q' to quit): ")
	
	# While loop so user can encrypt/decrypt more than one file at a time
	while init != 'q':
		choice = input("Would you like to (e)ncrypt or (d)ecrypt?: ")
	
		if choice == 'e':
			filename = input("File to encrypt: ")
			password = input("Password: ")
			encrypt(getKey(password), filename)
			print("Done.\n")
			init = input("Encrypt/Decrypt another file?('q' to quit): ")
		elif choice == 'd':
			filename = input("File to decrypt: ")
			password = input("Password: ")
			decrypt(getKey(password), filename)
			print("Done.\n")
			init = input("Encrypt/Decrypt another file?('q' to quit): ")
		else:
			print("No option selected, closing...")
			break
		
if __name__== '__main__':
	Main()
		
	
  
