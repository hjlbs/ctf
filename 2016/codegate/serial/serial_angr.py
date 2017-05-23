import angr

b = angr.Project("/vagrant/cg/f158d82c3a24c9de9e560713327b9c7e")
s = b.factory.blank_state(addr=0x400CBB)
v = s.se.BVS('key', 15*8)
s.memory.store( 0x51410000,  v )
s.regs.rdi=0x51410000

initpath = b.factory.path(state=s)
ex = b.surveyors.Explorer( start=initpath, find=(0x400E5C))
ex.run()

print ex.found[0].state.se.any_str( ex.found[0].state.memory.load(0x51410000, 13))
