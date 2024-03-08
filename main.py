#!/usr/bin/env python
#Equation of elliptic curve - y^2 = x^3 + ax + b

import  random
import hashlib
from Crypto.Cipher import AES
import hmac

def add_points (P, Q , p):
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 == y2:
        beta = (3*x1*x2) * pow(2*y1, -1, p)
    else :
        beta = (y2-y1) * pow(x2-x1,-1,p)
    x3 = (beta * beta - x1 - x2) % p
    y3 = (beta * (x1 - x3) - y1) % p
    is_on_curve((x3,y3), p)
    return x3,y3

def is_on_curve(P, p):
    x, y = P
    assert pow(y,2, p) == (pow(x ,3, p ) +a*x + b) % p

def apply_double_and_add_method(G , k , p):
    target_point = G
    k_binary = bin(k)[2:] # 0b1111111001
    for i in range (1, len(k_binary)):
        current_bit = k_binary[i : i+1] #used to extract a single bit from the total binary
        #doubling always
        target_point = add_points(target_point, target_point, p)
        if current_bit == "1":
            target_point = add_points(target_point,G , p)
    is_on_curve(target_point, p)
    return target_point



#Secp256k1
a = 0; b = 7
G = (55066263022277343669578718895168534326250603453777594175500187360389116729240,
32670510020758816978083085130507043184471273380659243275938904335757337482424)

p = pow(2, 256) - pow(2, 32) - pow(2, 9) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 4) - pow(2, 0)
n = 115792089237316195423570985008687907852837564279074904382605163141518161494337

is_on_curve(G, p) #if this is true the base point is on our curve

temp_point = G

result = apply_double_and_add_method(G,20,p)
#print(result)

#Here begins the great lore of alice and bob

#Alice generate her public and private key
ka = random.getrandbits(256) #private key of alice
Q = apply_double_and_add_method(G, ka , p) #public key of alice

#Bob generate his public and private key
kb = random.getrandbits(256)

#public -> send this key to Alice
U = apply_double_and_add_method(G, kb , p)

#private key -> keeps secret
Q = apply_double_and_add_method(Q, kb , p)


#key Derivation Function (Public)
def derive_keys(T):
    tx , ty = T
    tx_binary = bin(tx)[2:] #since binary in python contains b' in the begining so we have to start from index 2

    tx_binary_cropped = tx_binary[0:192]
    tx_restore = int(tx_binary_cropped, 2)

    #now applying sha256
    hash_hex = hashlib.sha256(str.encode(str(tx_restore))).hexdigest()
    hash_binary = bin(int(hash_hex, 16))[2:]

    #now we have to split this 256 bit keys to 128 bits +128 bits where the first 128 bits are used by symmetric encryption and the rest 128 bits are used by hmac
    k1 = int (hash_binary[0:128],2).to_bytes(16 , byteorder= "big")
    k2 = int (hash_binary[128:],2).to_bytes(16 , byteorder= "big")
    return k1, k2

def find_mac(cipher_text,key):
    hmac.new(key, cipher_text, hashlib.sha256).hexdigest()

#bob calling the derive key function
k1,k2 = derive_keys(result)

#Encryption -> AES 126
msg = "Attack Tomorrow ".encode()#this would be the hex value of the image

obj_bob = AES.new(k1, AES.MODE_CTR)
c = obj_bob.encrypt(msg)
hash_mac_of_message = find_mac(c, k2)

#BOB will sent (U,c,hash_mac_of_message) to Alice

print(f"Public key: {U}"
      f"Encrypted Message: {c}"
      f"Hash_mac:{hash_mac_of_message} "
      )


