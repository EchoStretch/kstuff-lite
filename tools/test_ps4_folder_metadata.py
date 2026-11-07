"""Compile and exercise real metadata I/O; no game files or console required."""

import ctypes as c, os, tempfile, subprocess, sys, shutil
from pathlib import Path

r = Path(__file__).resolve().parent.parent
build = tempfile.TemporaryDirectory(prefix="kstuff-folder-metadata-")
output = Path(build.name) / "reader.so"
cc = shutil.which("cc")
if not cc:
    raise SystemExit("A host C compiler is required")
subprocess.run(
    [
        cc,
        "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-dynamiclib" if sys.platform == "darwin" else "-shared",
        "-fPIC",
        str(r / "ps5-kstuff/shellcore_hook/ps4_folder_metadata.c"),
        "-o",
        str(output),
    ],
    check=True,
)
lib = c.CDLL(None)
plugin = c.CDLL(str(output))
error_location = getattr(
    lib, "__error" if sys.platform == "darwin" else "__errno_location"
)
lib.malloc.argtypes = [c.c_size_t]
lib.malloc.restype = c.c_void_p
lib.free.argtypes = [c.c_void_p]
error_location.restype = c.POINTER(c.c_int)
ORIG = c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_void_p, c.c_uint, c.c_void_p, c.c_void_p)
ALLOC = c.CFUNCTYPE(c.c_void_p, c.c_size_t)
FREE = c.CFUNCTYPE(None, c.c_void_p)
PREAD = c.CFUNCTYPE(c.c_long, c.c_int, c.c_void_p, c.c_size_t, c.c_long)
OPEN = c.CFUNCTYPE(c.c_int, c.c_char_p, c.c_int)


class Env(c.Structure):
    _fields_ = [
        (n, c.c_void_p)
        for n in (
            "original",
            "open",
            "pread",
            "close",
            "allocate",
            "release",
            "errno",
        )
    ] + [("filenames", (c.c_char * 16) * 2)]


allocated = set()
fallthrough = []


@ALLOC
def alloc(n):
    p = lib.malloc(n)
    allocated.add(p)
    return p


@FREE
def free(p):
    assert p in allocated
    allocated.remove(p)
    lib.free(p)


@ORIG
def orig(*args):
    fallthrough.append(args)
    return 123


ptr = lambda f: c.cast(f, c.c_void_p).value
env = Env(
    *map(ptr, (orig, lib.open, lib.pread, lib.close, alloc, free, error_location))
)
env.filenames[0].value = b"/nptitle.dat"
env.filenames[1].value = b"/npbind.dat"
f = plugin.ps4_folder_metadata_read
f.argtypes = [
    c.c_void_p,
    c.c_void_p,
    c.c_uint,
    c.POINTER(c.c_void_p),
    c.POINTER(c.c_size_t),
    c.POINTER(Env),
]
f.restype = c.c_int
with tempfile.TemporaryDirectory() as td:
    root = c.create_string_buffer(td.encode())
    source = c.create_string_buffer(32)
    c.c_uint.from_buffer(source, 8).value = 2
    c.c_void_p.from_buffer(source, 16).value = c.addressof(root)

    def run(entry=0x402):
        out = c.c_void_p()
        size = c.c_size_t()
        ret = f(source, 0x1234, entry, c.byref(out), c.byref(size), c.byref(env))
        data = c.string_at(out, size.value) if out.value else None
        if out.value:
            free(out.value)
        assert not allocated
        return ret & 0xFFFFFFFF, data, size.value

    p = Path(td) / "nptitle.dat"
    p.write_bytes(bytes(range(160)))
    assert run() == (0, bytes(range(160)), 160)
    (Path(td) / "npbind.dat").write_bytes(b"bind" * 133)
    assert run(0x403) == (0, b"bind" * 133, 532)
    root = c.create_string_buffer((td + "/").encode())
    c.c_void_p.from_buffer(source, 16).value = c.addressof(root)
    assert run()[2] == 160
    p.unlink()
    assert run() == (0, None, 0)
    p.write_bytes(b"")
    assert run()[0] == 0x80551611
    p.write_bytes(b"x" * (1024 * 1024 + 1))
    assert run()[0] == 0x80551611
    p.write_bytes(bytes(range(160)))
    reads = [0]

    @PREAD
    def short(fd, buf, n, offset):
        reads[0] += 1
        if reads[0] == 1:
            error_location()[0] = 4
            return -1
        b = os.pread(fd, min(n, 3), offset)
        c.memmove(buf, b, len(b))
        return len(b)

    env.pread = ptr(short)
    assert run()[1] == bytes(range(160)) and reads[0] > 50

    @PREAD
    def badread(*args):
        error_location()[0] = 5
        return -1

    env.pread = ptr(badread)
    assert run()[0] == 0x80020005
    env.pread = ptr(lib.pread)

    @OPEN
    def denied(*args):
        error_location()[0] = 13
        return -1

    env.open = ptr(denied)
    assert run()[0] == 0x8002000D
    env.open = ptr(lib.open)

    @ALLOC
    def noalloc(n):
        return None

    env.allocate = ptr(noalloc)
    assert run()[0] == 0x80551603
    env.allocate = ptr(alloc)
    assert run(0x404)[0] == 0x80551604
    c.c_uint.from_buffer(source, 8).value = 1
    assert run()[0] == 123
    assert fallthrough[-1][1:3] == (0x1234, 0x402)
    c.c_uint.from_buffer(source, 8).value = 2
    root = c.create_string_buffer(b"x" * 1024)
    c.c_void_p.from_buffer(source, 16).value = c.addressof(root)
    assert run()[0] == 0x80551605
print(
    "PASS: file contents, absent/empty/oversize files, short reads/EINTR, EIO, EACCES, OOM, path bounds, fallback ABI, allocation cleanup"
)


build.cleanup()
