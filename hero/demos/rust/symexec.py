# Find the input that gets accepted
import angr
proj = angr.Project("fauxware")
cfg = proj.analyses.CFGFast(normalize=True)
funcs = {f.demangled_name: f for f in cfg.functions.values()}

# skip the Rust runtime's startup: start right at fauxware::main
state = proj.factory.blank_state(addr=funcs["fauxware::main"].addr)
simgr = proj.factory.simgr(state)
simgr.explore(find=funcs["fauxware::accepted"].addr)

print(simgr.found[0].posix.dumps(0).rstrip(b"\x00"))
