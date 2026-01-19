#!/bin/python

from pwn import *

pr = process("/challenge/run")

pr.recvuntil(b"p = 0x")
p = int(pr.recvline().strip().decode(), 16)

pr.recvuntil(b"e = 0x")
e = int(pr.recvline().strip().decode(), 16)

pr.recvuntil(b"q = 0x")
q = int(pr.recvline().strip().decode(), 16)

pr.recvuntil(b"Flag Ciphertext (hex): ")
flag = int(pr.recvline().strip().decode(), 16)

n = p * q
phi = (p - 1) * (q - 1)
d = inverse(e, phi)
d = pow(e, -1, phi)

pt = pow(flag, d, n)
print(pt)
