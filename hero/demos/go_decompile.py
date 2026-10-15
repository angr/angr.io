# title: Go Decompilation
# terminal: age
# Decompile a method of age (filippo.io/age) to Go pseudocode
import angr
proj = angr.Project("go/age", auto_load_libs=False)
cfg = proj.analyses.CFGFast(normalize=True)

dec = proj.analyses.Decompiler(
    "filippo.io/hpke.(*hybridPrivateKey).decap", flavor="go"
)
print(dec.codegen.text)
