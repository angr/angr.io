# Decompile a Go binary's main.main — back to Go
import angr
proj = angr.Project("fauxware")
cfg = proj.analyses.CFGFast(normalize=True)

proj.analyses.CompleteCallingConventions()
dec = proj.analyses.Decompiler("main.main", flavor="go")
print(dec.codegen.text)
