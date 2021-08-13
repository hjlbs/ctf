#!/usr/bin/env python
import angr
import sys
import claripy
from pwn import *

def main():
    ## Base of the challenge binary
    base = 0x100000

    ## After the scanf there is a check to make sure that the length
    ##  of the input is exactly 0x1e
    input_len = 0x1e

    p = angr.Project('./chall', main_opts={'base_addr': base})

    ## I need the state. Set the start address to just after the scanf
    state = p.factory.blank_state(addr=0x100b84)

    ## Address of the input data
    input_addr = 0x302100

    ## put constraints on the state
    for i in range(input_len):
        ## Get a symbolic byte
        ch = state.solver.BVS('ch{}'.format(i), 8)
        
        if i == 0:
            state.solver.add(ch == ord('p'))
        if i == 1:
            state.solver.add(ch == ord('L'))
        if i == 2:
            state.solver.add(ch == ord('U'))
        if i == 3:
            state.solver.add(ch == ord('T'))
        if i == 4:
            state.solver.add(ch == ord('0'))

        ## must be valid ascii
        state.solver.add(ch > 0x20)
        state.solver.add(ch <= 0x7e)
        state.solver.add(ch != ord('`'))
        state.solver.add(ch != ord('"'))
        state.solver.add(ch != ord('\''))
        state.solver.add(ch != ord('='))
        state.solver.add(ch != ord(','))
        state.solver.add(ch != ord('%'))
        state.solver.add(ch != ord('*'))
        state.solver.add(ch != ord('+'))
        state.solver.add(ch != ord(';'))

        state.memory.store(input_addr + i, ch)

    simmgr = p.factory.simulation_manager(state)

    simmgr.explore(find=0x100adb, avoid=0x1008aa)

    if simmgr.found[0]:
        found_state = simmgr.found[0]

        inputa = found_state.memory.load(input_addr, 0x1e)
        output = found_state.solver.eval(inputa, cast_to=bytes)

        print(type(output))
        print(f'Da data: {output}')

        p = remote('34.94.181.140', 4205)
        p.readline()
        p.readline()
        p.send(output + b'\n')

        y = p.readuntil(b'}').split(b'\n')

        print(y[-1])

    else:
        print('Not found')
    
main()
