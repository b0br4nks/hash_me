import hashlib
import sys
import os

mag = "\033[0;35;40m"
cya = "\033[0;36;40m"
whi = "\033[1;37;40m"

print(f"""{mag}
██   ██  █████  ███████ ██   ██         ███    ███ ███████ 
██   ██ ██   ██ ██      ██   ██         ████  ████ ██      
███████ ███████ ███████ ███████         ██ ████ ██ █████   
██   ██ ██   ██      ██ ██   ██         ██  ██  ██ ██      
██   ██ ██   ██ ███████ ██   ██ ███████ ██      ██ ███████                                                  
""")

file = input(f"{cya}[?]Enter the name of the file: ")

def checksum(file):
    BUFFER_SIZE = 16384 #16KB
    b = b""
    with open(file, "rb") as f:
        while True:
            bytes_read = f.read(BUFFER_SIZE)
            if bytes_read:
                b += bytes_read
            else:
                break
    return b

if __name__ == "__main__":

    z = checksum(file)
    
    print(f"{mag}[!]MD5:", f"{whi}"+hashlib.md5(z).hexdigest()),
    print(f"{mag}[!]SHA-256:", f"{whi}"+hashlib.sha256(z).hexdigest()),
    print(f"{mag}[!]SHA-512:", f"{whi}"+hashlib.sha512(z).hexdigest()),
    print(f"{mag}[!]SHA-3-256:", f"{whi}"+hashlib.sha3_256(z).hexdigest()),
    print(f"{mag}[!]SHA-3-512:", f"{whi}"+hashlib.sha3_512(z).hexdigest()),
    print(f"{mag}[!]SHA-1:", f"{whi}"+hashlib.sha1(z).hexdigest()),
    print(f"{mag}[!]SHA-224:", f"{whi}"+hashlib.sha224(z).hexdigest()),
    print(f"{mag}[!]SHA-384:", f"{whi}"+hashlib.sha384(z).hexdigest()),
    print(f"{mag}[!]BLAKE2c:", f"{whi}"+hashlib.blake2s(z).hexdigest()),
    print(f"{mag}[!]BLAKE2b:", f"{whi}"+hashlib.blake2b(z).hexdigest()),

def print_hash():
    print("MD5:",      hashlib.md5(z).hexdigest()),
    print("SHA-256:",  hashlib.sha256(z).hexdigest()),
    print("SHA-512:",  hashlib.sha512(z).hexdigest()),
    print("SHA-3-256:",hashlib.sha3_256(z).hexdigest()),
    print("SHA-3-512:",hashlib.sha3_512(z).hexdigest()),
    print("SHA-1:",    hashlib.sha1(z).hexdigest()),
    print("SHA-224:",  hashlib.sha224(z).hexdigest()),
    print("SHA-384:",  hashlib.sha384(z).hexdigest()),
    print("BLAKE2c:",  hashlib.blake2s(z).hexdigest()),
    print("BLAKE2b:",  hashlib.blake2b(z).hexdigest()),

save = input(f"{cya}[?]Do you want to save the hash to a file? [y/n]: ")
if save == "y":
    original_stdout = sys.stdout
    f = open(f'{os.path.splitext(file)[0]}.hash_me', 'w')
    sys.stdout = f
    print_hash()
    sys.stdout = original_stdout
    f.close()
    print(f"{mag}[!]Saved as {os.path.splitext(file)[0]}.hash_me")
else:
    print(f"{mag}[!]Ok, bye!")
