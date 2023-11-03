from pwn import *

eLevel5 = ELF('./level5')

addrWrite = eLevel5.got["write"]

print(hex(addrWrite))
