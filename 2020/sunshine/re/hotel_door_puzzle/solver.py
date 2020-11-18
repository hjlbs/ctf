import angr
import claripy
import sys

def main(argv):
  base_addr = 0x4100000
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary, main_opts={'base_addr':base_addr})

  start_address = 0x41022a9
  initial_state = project.factory.blank_state(addr=start_address)

  initial_state.regs.rbp = initial_state.regs.rsp

  ## padding for the stack
  initial_state.regs.rsp -= 0x60

  flag = claripy.BVS('flag', 60*8)

  flag_address = initial_state.regs.rsp + 0x10

  initial_state.memory.store(flag_address, flag)

  simulation = project.factory.simgr(initial_state)

  simulation.explore(find=0x41022c1, avoid=0x041022cf)

  if simulation.found:
    solution_state = simulation.found[0]

    solution = solution_state.se.eval(flag,cast_to=bytes)

    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
