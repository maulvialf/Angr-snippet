#xva Solver

import angr
import claripy

FLAG_LEN = 32
STDIN_FD = 0

base_addr = 0x000000

proj = angr.Project("./xva", main_opts={'base_addr': base_addr})

flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(FLAG_LEN)]
flag = claripy.Concat( *flag_chars + [claripy.BVV(b'\n')])

state = proj.factory.full_init_state(
        args=['xva'],
        add_options=angr.options.unicorn,
        stdin=flag,
)

# Add constraints that all characters are printable
for k in flag_chars:
    state.solver.add(k >= ord('!'))
    state.solver.add(k <= ord('~'))

simgr = proj.factory.simulation_manager(state)
find_addr  = 0x1aff # SUCCESS
avoid_addr = 0x1B10 # FAILURE
simgr.explore(find=find_addr, avoid=avoid_addr)

if (len(simgr.found) > 0):
    for found in simgr.found:
        print(found.posix.dumps(STDIN_FD))
