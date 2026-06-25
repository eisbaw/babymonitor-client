# Decompile selected libthing_security.so auth-related functions.
#@category Reverse
#@runtime Jython

from ghidra.app.decompiler import DecompInterface


TARGETS = [
    0x00116000,  # getChKey
    0x00116408,  # testSign
    0x00113d50,  # JNI_OnLoad
]


decomp = DecompInterface()
if not decomp.openProgram(currentProgram):
    print("decompiler_open_failed: %s" % decomp.getLastMessage())
    raise SystemExit(1)

fm = currentProgram.getFunctionManager()
space = currentProgram.getAddressFactory().getDefaultAddressSpace()

for value in TARGETS:
    address = space.getAddress(value)
    fn = fm.getFunctionAt(address)
    if fn is None:
        fn = fm.getFunctionContaining(address)
    if fn is None:
        print("missing_function 0x%x" % value)
        continue
    result = decomp.decompileFunction(fn, 90, monitor)
    if not result.decompileCompleted():
        print("decompile_failed %s %s" % (address, result.getErrorMessage()))
        continue
    print("\n/* DECOMPILED %s %s */" % (address, fn.getName()))
    print(result.getDecompiledFunction().getC())
