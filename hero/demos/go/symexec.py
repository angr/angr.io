# Find the input that gets accepted
import angr
proj = angr.Project("fauxware")
main = proj.loader.find_symbol("main.main").rebased_addr
accepted = proj.loader.find_symbol("main.accepted").rebased_addr
morestack = proj.loader.find_symbol("runtime.morestack_noctxt.abi0").rebased_addr

# skip the Go runtime's bootstrap: start right at main.main
state = proj.factory.blank_state(addr=main)
simgr = proj.factory.simgr(state)
simgr.explore(find=accepted, avoid=morestack)

print(simgr.found[0].posix.dumps(0))
