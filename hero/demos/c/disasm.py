# Disassemble a function with its CFG edges
import angr
proj = angr.Project("fauxware")
proj.analyses.CFGFast(normalize=True)
proj.kb.functions["authenticate"].pp()
