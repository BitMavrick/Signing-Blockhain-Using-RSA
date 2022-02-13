import random
from hashlib import sha256

###
#  Author :       Mehedi Hasan
#  Institute :    Daffodil Internation University
#  Source-code :  SilverCoin Secure Transaction Protocol [Using Signing-Blockchain and RSA Cryptosystem]
#  Project :      SilverPay    
#  Technology :   Python 3.9.9 [64-bit]
###

def coprime(a, b):
    while b != 0:
        a, b = b, a % b
    return a
    
    
def extended_gcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)

# Euclid's extended algorithm for finding the multiplicative inverse of two numbers    
def modinv(a, m):
	g, x, y = extended_gcd(a, m)
	if g != 1:
		raise Exception('Modular inverse does not exist')
	return x % m    

        
def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num**0.5)+2, 2):
        if num % n == 0:
            return False
    return True


def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')

    n = p * q

    # Phi is the totient of n
    phi = (p-1) * (q-1)

    # Choose an integer e such that e and phi(n) are coprime
    e = random.randrange(1, phi)

    # Use Euclid's Algorithm to verify that e and phi(n) are comprime 
    g = coprime(e, phi)
  
    while g != 1:
        e = random.randrange(1, phi)
        g = coprime(e, phi)

    # Use Extended Euclid's Algorithm to generate the private key
    d = modinv(e, phi)

    # Return public and private keypair
    # Public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))


def encrypt(public_key, plaintext):
    # Unpack the key into it's components
    key, n = public_key

    # Convert each letter in the plaintext to numbers based on the character using a^b mod m
            
    numberRepr = [ord(char) for char in plaintext]
    # print("\nNumeric representation before encryption: ", numberRepr) # Run for development purpose
    cipher = [pow(ord(char),key,n) for char in plaintext]
    
    # Return the array of bytes
    return cipher


def decrypt(private_key, ciphertext):
    # Unpack the key into its components
    key, n = private_key
       
    # Generate the plaintext based on the ciphertext and key using a^b mod m
    numberRepr = [pow(char, key, n) for char in ciphertext]
    plain = [chr(pow(char, key, n)) for char in ciphertext]

    # print("\nRestore numeric representation : ", numberRepr) # Run for development purpose
    
    
    # Return the array of bytes as a string
    return ''.join(plain)
    
    
def hashFunction(data):
    hashed = sha256(data.encode("UTF-8")).hexdigest()
    return hashed
        

# Start From Here...

def main():

    ###
    # First the system have to generate 2 prime number for calculate publice and private key pairs.
    # In our main system, p and q will be randomly generated prime number.
    ###
       
    p = 17
    q = 23
    
    print("\nGenerating your public/private keypairs ...")
    public, private = generate_keypair(p, q) # Generating publice and private key for receivers.

    ###
    # Transaction Process:
    # 1. The transaction data will be encrypted by receivers public key.
    # 2. The data can only be decrypt by the receivers private key.
    ###
    
    print("\nReceivers public key is ", public ,"\n\nReceivers private key is ", private)
    the_data = input("\nEnter the transaction data to encrypt with receivers public key: ")
    print("")

    print("Encrypting message with public key ", public ," ...")
    encrypted_data = encrypt(public, the_data)   
    print("Your encrypted data : ")
    print(''.join(map(lambda x: str(x), encrypted_data)))

    
    print("")
    print("Decrypting data with private key ", private ," ...")

    decrypted_data = decrypt(private, encrypted_data)
    print("Your decrypted data is : ", decrypted_data)  
    print("")

    ###
    # Blockchain generation process:
    # 1. Each transaction creates 2 block
    #   > One : | New Block | to the sender-end.
    #   > Two : | Previous Block | to the receiver-end.
    #   > Both value will be same.
    #
    # 2. Block will be hashed before creating the chain.
    ###

    block = hashFunction(decrypted_data)
    print('The transaction block :')
    print('\nSender new block : ', block)
    print('\nReceiver previous block : ', block)
    print("")
    
   
main() # Calling Strating method