# Decompile main() to readable C
import angr
proj = angr.Project("fauxware")
cfg = proj.analyses.CFGFast(normalize=True)

dec = proj.analyses.Decompiler("main")
print(dec.codegen.text)
