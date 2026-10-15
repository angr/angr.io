# Find the input that gets accepted
import angr
proj = angr.Project("fauxware")
simgr = proj.factory.simgr()

accepted = proj.loader.find_symbol("accepted").rebased_addr
simgr.explore(find=accepted)

print(simgr.found[0].posix.dumps(0))
