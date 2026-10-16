# Decompile a Rust binary's main — back to Rust. Based on "Oxidizer: Toward
# Concise and High-fidelity Rust Decompilation" (Yibo Liu et al.,
# IEEE S&P 2026).
import angr
proj = angr.Project("fauxware")
cfg = proj.analyses.CFGFast(normalize=True)

proj.analyses.CompleteCallingConventions()
proj.analyses.RustSymbolRecovery()
proj.analyses.TypeDBLoader()
funcs = {f.demangled_name: f for f in cfg.functions.values()}

dec = proj.analyses.Decompiler(funcs["fauxware::main"], flavor="rust")
print(dec.codegen.text)
