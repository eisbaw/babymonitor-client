# Full decompile of a native lib: every function -> per-function .c file,
# plus a function index, defined-strings dump, and imports/exports list.
# Output dir is taken from env GHIDRA_DUMP_DIR (must exist).
#@category Reverse
#@runtime Jython

import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

out_dir = os.environ.get("GHIDRA_DUMP_DIR")
if not out_dir:
    print("GHIDRA_DUMP_DIR_unset")
    raise SystemExit(1)
funcs_dir = os.path.join(out_dir, "funcs")
if not os.path.isdir(funcs_dir):
    os.makedirs(funcs_dir)

monitor = ConsoleTaskMonitor()
decomp = DecompInterface()
if not decomp.openProgram(currentProgram):
    print("decompiler_open_failed: %s" % decomp.getLastMessage())
    raise SystemExit(1)

fm = currentProgram.getFunctionManager()


def safe(name):
    keep = []
    for ch in name:
        if ch.isalnum() or ch in "_.-":
            keep.append(ch)
        else:
            keep.append("_")
    return "".join(keep)[:120]


# 1) decompile every function
index_lines = []
count = 0
fns = fm.getFunctions(True)
for fn in fns:
    addr = fn.getEntryPoint()
    name = fn.getName()
    index_lines.append("%s\t%s\t%d" % (addr, name, fn.getParameterCount()))
    try:
        result = decomp.decompileFunction(fn, 120, monitor)
    except Exception as exc:
        print("decompile_exception %s %s" % (addr, exc))
        continue
    if not result.decompileCompleted():
        # still emit a stub so the index is complete
        body = "/* DECOMPILE_FAILED %s: %s */\n" % (addr, result.getErrorMessage())
    else:
        body = result.getDecompiledFunction().getC()
    fname = "%s_%s.c" % (str(addr), safe(name))
    f = open(os.path.join(funcs_dir, fname), "w")
    f.write("/* FUNC %s @ %s */\n" % (name, addr))
    f.write(body)
    f.close()
    count += 1

f = open(os.path.join(out_dir, "index.txt"), "w")
f.write("# address\tname\tparam_count\n")
f.write("\n".join(index_lines))
f.close()

# 2) defined strings
st = open(os.path.join(out_dir, "strings.txt"), "w")
listing = currentProgram.getListing()
data_iter = listing.getDefinedData(True)
nstr = 0
for d in data_iter:
    dt = d.getDataType().getName().lower()
    if "char" in dt or "string" in dt or "unicode" in dt:
        try:
            val = d.getValue()
        except Exception:
            val = None
        if val is None:
            continue
        s = str(val)
        s = s.replace("\n", "\\n").replace("\r", "\\r")
        if len(s.strip()) == 0:
            continue
        st.write("%s\t%s\n" % (d.getAddress(), s))
        nstr += 1
st.close()

# 3) imports / exports
sym = open(os.path.join(out_dir, "symbols.txt"), "w")
st_tab = currentProgram.getSymbolTable()
sym.write("# === EXTERNAL (imports) ===\n")
for s in st_tab.getExternalSymbols():
    sym.write("IMPORT\t%s\n" % s.getName())
sym.write("# === GLOBAL (exports/defined) ===\n")
for s in st_tab.getDefinedSymbols():
    if s.isGlobal() and s.isExternalEntryPoint():
        sym.write("EXPORT\t%s\t%s\n" % (s.getAddress(), s.getName()))
sym.close()

print("decompiled_functions=%d strings=%d out=%s" % (count, nstr, out_dir))
