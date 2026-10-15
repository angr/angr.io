# Disassemble a Rust function — angr demangles the symbols
import angr
proj = angr.Project("fauxware")
cfg = proj.analyses.CFGFast(normalize=True)
funcs = {f.demangled_name: f for f in cfg.functions.values()}
funcs["fauxware::authenticate"].pp()
