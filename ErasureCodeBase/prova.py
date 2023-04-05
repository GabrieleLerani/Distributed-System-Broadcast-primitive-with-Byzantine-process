import unireedsolomon as rs
# N= length of the data; K= length of the min correct data ro decode
coder = rs.RSCoder(20,13)

        # encode data
c = coder.encode("Hello, world!")

print(len(c))
print(c[13:])
print(len(c[13:]))

print(len(c[6:]),len(c),len(c[3:]),len("\0"*6 + c[13:]+c[:7]))

print(c[3:])

r = "\0"*6 + c[13:]+c[:7]

#print(repr(r))

        # regenerate lost data
s=coder.decode('\x00\x00\x00lo, world!\x8d\x13\xf4\xf9C\x10\xe5')

print(s)


secret, shares = make_random_secret(3, 5)
# generate shares such that 3 of 5 can recover the secret
secret = recover_secret(shares)

from binascii import hexlify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir

key = get_random_bytes(16)
shares = Shamir.split(2, 5, key)
for idx, share in shares:
    print("Index #%d: %s" % (idx, hexlify(share)))

with open("clear.txt", "rb") as fi, open("enc.txt", "wb") as fo:
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt(fi.read()), cipher.digest()
    fo.write(cipher.nonce + tag + ct)



shares = []
for x in range(2):
    in_str = raw_input("Enter index and share separated by comma: ")
    idx, share = [ strip(s) for s in in_str.split(",") ]
    shares.append((idx, unhexlify(share)))
key = Shamir.combine(shares)

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