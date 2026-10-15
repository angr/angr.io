# title: Rust Decompilation
# terminal: grex
# Rust pseudocode for grex's main(). Based on "Oxidizer: Toward
# Concise and High-fidelity Rust Decompilation" (Yibo Liu et al.,
# IEEE S&P 2026).
import angr
proj = angr.Project("rust/grex", auto_load_libs=False)
cfg = proj.analyses.CFGFast(normalize=True)
main = next(f for f in proj.kb.functions.values()
            if f.demangled_name == "grex::main")
cc = proj.analyses.CompleteCallingConventions(
    prioritize_func_addrs=[main.addr], skip_other_funcs=True)

# rustc version, std signatures and std type layouts
proj.analyses.RustcVersionIdentification()
proj.analyses.RustSymbolRecovery()
proj.analyses.TypeDBLoader()
dec = proj.analyses.Decompiler(main, flavor="rust")
print(dec.codegen.text)
