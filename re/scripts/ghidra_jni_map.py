# Lists likely JNI native-method table rows for libthing_security.so.
#@category Reverse
#@runtime Jython

from jarray import zeros


METHOD_NAMES = [
    "computeDigest",
    "decryptResponseData",
    "doCommandNative",
    "encryptPostData",
    "genKey",
    "getChKey",
    "getConfig",
    "getEncryptoKey",
    "testSign",
]


mem = currentProgram.getMemory()
listing = currentProgram.getListing()
functions = currentProgram.getFunctionManager()


def u8(b):
    return b & 0xFF


def read_u64(address):
    buf = zeros(8, "b")
    mem.getBytes(address, buf)
    value = 0
    for i in range(8):
        value |= u8(buf[i]) << (8 * i)
    return value


def read_cstr(address, limit=256):
    chars = []
    for i in range(limit):
        b = u8(mem.getByte(address.add(i)))
        if b == 0:
            break
        if b < 0x20 or b > 0x7E:
            return None
        chars.append(chr(b))
    return "".join(chars)


def addr(value):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value)


def find_defined_strings():
    out = {}
    data_iter = listing.getDefinedData(True)
    while data_iter.hasNext():
        data = data_iter.next()
        try:
            value = data.getValue()
        except Exception:
            continue
        if value is None:
            continue
        text = str(value)
        if text in METHOD_NAMES:
            out[text] = data.getAddress()
    return out


def find_u64(value):
    hits = []
    for block in mem.getBlocks():
        if not block.isInitialized():
            continue
        start = block.getStart()
        end = block.getEnd()
        cur = start
        while cur.compareTo(end) <= 0:
            if cur.getOffset() % 8 == 0:
                try:
                    if read_u64(cur) == value:
                        hits.append(cur)
                except Exception:
                    pass
            cur = cur.add(1)
    return hits


def function_name(function_address):
    fn = functions.getFunctionAt(function_address)
    if fn is None:
        fn = functions.getFunctionContaining(function_address)
    if fn is None:
        return "<no function>"
    return fn.getName()


print("program=%s imageBase=%s" % (currentProgram.getName(), currentProgram.getImageBase()))
for fn in functions.getFunctions(True):
    if fn.getName() == "JNI_OnLoad":
        print("JNI_OnLoad=%s" % fn.getEntryPoint())

strings = find_defined_strings()
for name in METHOD_NAMES:
    saddr = strings.get(name)
    if saddr is None:
        print("missing_string name=%s" % name)
        continue

    pointer_hits = find_u64(saddr.getOffset())
    if not pointer_hits:
        print("no_table_pointer name=%s string=%s" % (name, saddr))
        continue

    for hit in pointer_hits:
        try:
            sig_ptr = addr(read_u64(hit.add(8)))
            fn_ptr = addr(read_u64(hit.add(16)))
            sig = read_cstr(sig_ptr) or "<non-ascii>"
            print(
                "native name=%s table=%s string=%s sig=%s fn=%s fn_name=%s"
                % (name, hit, saddr, sig, fn_ptr, function_name(fn_ptr))
            )
        except Exception as e:
            print("bad_table name=%s table=%s error=%s" % (name, hit, e))
