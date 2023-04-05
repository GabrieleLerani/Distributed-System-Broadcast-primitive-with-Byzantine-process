from binascii import hexlify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir
from binascii import unhexlify
from base64 import b64decode,b64encode

key = get_random_bytes(16)
shares = Shamir.split(2, 5, key)
for idx, share in shares:
    print("Index #%d: %s" % (idx, hexlify(share)))

#with open("clear.txt", "rb") as fi, open("enc.txt", "wb") as fo:
with open("enc.txt", "wb") as fo:
    cipher = AES.new(key, AES.MODE_EAX)
    msg="EEEEEEEE"
    ct, tag = cipher.encrypt(msg.encode()), cipher.digest()
    fo.write(cipher.nonce + tag + ct)
    print(cipher.nonce + tag + ct)
    emsg = b64encode(cipher.nonce + tag + ct)
    print(ct)




#shares = []
#for x in range(2):
 #   in_str = input("Enter index and share separated by comma: ")
    #idx, share = [ strip(s) for s in in_str.split(",") ]
    #shares.append((idx, unhexlify(share)))
   
    #i=in_str.split(",")
  #  idx=i[0]
   # share=i[1]
    #shares.append((idx, unhexlify(share)))
print(shares[:2])
key = Shamir.combine(shares[:2])

with open("enc.txt", "rb") as fi:
    nonce, tag = [ fi.read(16) for x in range(2) ]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    try:
        result = cipher.decrypt(fi.read())
        cipher.verify(tag)
        with open("clear2.txt", "wb") as fo:
            fo.write(result)
    except ValueError:
        print("The shares were incorrect")






