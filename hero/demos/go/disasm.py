# Disassemble a Go function with its CFG edges
import angr
proj = angr.Project("fauxware")
proj.analyses.CFGFast(normalize=True)
proj.kb.functions["main.authenticate"].pp()
