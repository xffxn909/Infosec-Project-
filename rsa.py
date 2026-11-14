import sys
import random

input_file = sys.argv[1] if len(sys.argv) > 1 else "original.docx"


def is_prime(n):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(20):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    while True:
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1
        if is_prime(n):
            return n


print("Encryption:")

e = 65537
while True:
    p = generate_prime(512)
    q = generate_prime(512)
    phi = (p - 1) * (q - 1)
    if p != q and phi % e != 0:
        break

n = p * q
d = pow(e, -1, phi)

with open("public.pem", "w") as f:
    f.write("RSA PUBLIC KEY\n")
    f.write("n=" + str(n) + "\n")
    f.write("e=" + str(e) + "\n")

with open("private.pem", "w") as f:
    f.write("RSA PRIVATE KEY\n")
    f.write("n=" + str(n) + "\n")
    f.write("d=" + str(d) + "\n")

print("Keys generated: private.pem, public.pem")

with open(input_file, "rb") as f:
    data = f.read()

print("File read:", input_file, "(" + str(len(data)) + " bytes)")

key_bytes = (n.bit_length() + 7) // 8
chunk_size = key_bytes - 2

encrypted = bytearray()
for i in range(0, len(data), chunk_size):
    chunk = b"\x01" + data[i:i + chunk_size]
    m = int.from_bytes(chunk, "big")
    c = pow(m, e, n)
    encrypted += c.to_bytes(key_bytes, "big")

with open("encrypted.bin", "wb") as f:
    f.write(encrypted)

print("Encrypted file saved: encrypted.bin (" + str(len(encrypted)) + " bytes)")

print()
print("Decryption:")

with open("private.pem", "r") as f:
    lines = f.read().split("\n")

n2 = int(lines[1].split("=")[1])
d2 = int(lines[2].split("=")[1])

with open("encrypted.bin", "rb") as f:
    encrypted_data = f.read()

print("File read: encrypted.bin (" + str(len(encrypted_data)) + " bytes)")

block_size = (n2.bit_length() + 7) // 8

decrypted = bytearray()
for i in range(0, len(encrypted_data), block_size):
    c = int.from_bytes(encrypted_data[i:i + block_size], "big")
    m = pow(c, d2, n2)
    chunk = m.to_bytes((m.bit_length() + 7) // 8, "big")
    decrypted += chunk[1:]

with open("decrypted.docx", "wb") as f:
    f.write(decrypted)

print("Decrypted file saved: decrypted.docx (" + str(len(decrypted)) + " bytes)")
print("Decrypted file matches original:", bytes(decrypted) == data)