#!/usr/bin/env python
"""Apply a declarative binary-patch recipe to a PE32 image.

    python apply.py zone/recipes/mob-spawn-group-cap.json --exe Z:/ServerSource/Zone00/Zone.exe --out build/Zone.exe
    python apply.py zone/recipes/mob-spawn-group-cap.json --exe ... --dry-run
    python apply.py zone/recipes/mob-spawn-group-cap.json --exe ... --verify build/Zone.exe

Stdlib only, on purpose: a recipe you cannot run because a dependency moved is not repeatable.

THREE RULES THIS TOOL ENFORCES, because each corresponds to a way binary patching goes wrong quietly:

  1. NEVER IN PLACE. The input is opened read-only and the result is written to a new file. A half-applied
     patch over the only copy of a 2.7MB binary is unrecoverable.
  2. EVERY EDIT DECLARES WHAT IT EXPECTS TO FIND. If the bytes at a site are not what the recipe says,
     nothing is written at all. A patch that lands on the wrong offset does not crash -- it corrupts one
     instruction and the process dies somewhere unrelated a week later.
  3. ALL OR NOTHING. Sites are validated up front, then applied to an in-memory copy. There is no state
     where half the constants have been changed.
"""
import argparse
import hashlib
import json
import os
import re
import struct
import sys

# One shared arena instead of a section per recipe - see Pe.reserve(). Two, because page protection is a
# property of the section, so code and data cannot share one.
ARENA_DATA = ".zarena"
ARENA_EXEC = ".zarenax"
ARENA_MAGIC = b"ZARENA\0\0"
# The arena header, at the start of .zarena:
#   +0   magic
#   +8   high-water mark, +12 reserved size
#   +16  a DIRECTORY of the regions handed out: label[20], offset, size, flags. 32 bytes each.
#
# The directory is what makes --verify work. A region's address now depends on which recipes ran before
# it, so nothing outside the image can recompute it - without this, verify recomputed a fresh-section
# address and reported 8 of 12 recipes as broken when they were fine. The image describes itself instead.
ARENA_HEADER = 0x400
ARENA_DIR_AT = 16
ARENA_DIR_ENTRY = 32
ARENA_DIR_MAX = (ARENA_HEADER - ARENA_DIR_AT) // ARENA_DIR_ENTRY
ARENA_FLAG_EXEC = 1
# Code caves only: 0x1000 each, three recipes use one today. Fixed because the data arena sits
# after it and growing it in place would overlap - raise this and rebuild the chain if it fills.
ARENA_EXEC_SIZE = 0x10000

SECTION_ALIGNMENT_FALLBACK = 0x1000
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000


class Pe:
    """Just enough PE32 to map VA<->file offset and append a section. Hand-parsed rather than pulling in
    pefile: the header edits here are small and explicit, and a reader can check them against the spec."""

    def __init__(self, data: bytearray):
        self.d = data
        if data[:2] != b"MZ":
            raise ValueError("not a PE: no MZ")
        self.e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[self.e_lfanew:self.e_lfanew + 4] != b"PE\0\0":
            raise ValueError("not a PE: no PE signature")
        coff = self.e_lfanew + 4
        self.machine, self.n_sections = struct.unpack_from("<HH", data, coff)
        self.size_opt = struct.unpack_from("<H", data, coff + 16)[0]
        self.opt = coff + 20
        magic = struct.unpack_from("<H", data, self.opt)[0]
        if magic != 0x10B:
            raise ValueError(f"only PE32 is supported (optional header magic 0x{magic:X})")
        self.image_base = struct.unpack_from("<I", data, self.opt + 28)[0]
        self.section_alignment = struct.unpack_from("<I", data, self.opt + 32)[0] or SECTION_ALIGNMENT_FALLBACK
        self.file_alignment = struct.unpack_from("<I", data, self.opt + 36)[0] or 0x200
        self.size_of_image_off = self.opt + 56
        self.size_of_image = struct.unpack_from("<I", data, self.size_of_image_off)[0]
        self.sec_table = self.opt + self.size_opt
        self.sections = []
        for i in range(self.n_sections):
            o = self.sec_table + 40 * i
            name = bytes(data[o:o + 8]).rstrip(b"\0").decode("latin-1")
            vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
            self.sections.append(dict(name=name, off=o, vsize=vsize, va=va, rawsize=rawsize, rawptr=rawptr))
        self.arena_log = []

    def offset_of(self, va: int):
        """File offset for a virtual address, or None when the VA is not backed by file bytes."""
        rva = va - self.image_base
        for s in self.sections:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
                delta = rva - s["va"]
                if delta >= s["rawsize"]:
                    return None            # inside the section's zero-fill tail
                return s["rawptr"] + delta
        return None

    def data_directory(self, index: int):
        """(RVA, size) of one data directory, and where its header field lives."""
        n = struct.unpack_from("<I", self.d, self.opt + 92)[0]
        if index >= n:
            raise ValueError(f"image has only {n} data directories")
        at = self.opt + 96 + index * 8
        rva, size = struct.unpack_from("<II", self.d, at)
        return rva, size, at

    def add_import(self, dll: str, func: str, section: str = ".zhook"):
        """Make the loader pull `dll` in before the entry point runs, by rebuilding the import descriptor
        array in a new section with one extra entry.

        WHY THIS AND NOT A CODE PATCH: the Windows loader already knows how to map a DLL and run its
        DllMain, and it does so before any of the exe's own code - including the CRT - executes. An
        injected LoadLibrary call has to pick a moment that is late enough for the CRT and early enough
        to matter, and gets that wrong on exactly the paths that are hard to test. Adding an import is
        also reversible by rewriting one data directory, and it leaves every original byte of .text
        alone, so a recipe that does this composes with every other recipe in this repo.

        SAFE HERE because the image has no bound-import directory (checked below): a bound image caches
        resolved addresses and a loader that trusts them can skip the descriptor array entirely, which
        would silently drop the new entry. The original descriptors are COPIED, not moved - their ILT,
        IAT and name RVAs still point into .rdata and stay valid.

        The DLL must export `func`; it is imported by name so the loader fails loudly (a message box
        naming the missing export) rather than leaving a null in the IAT that nothing ever calls.
        """
        bound_rva, bound_size, _ = self.data_directory(11)
        if bound_rva or bound_size:
            raise ValueError("image has a bound-import directory; rebuilding imports needs it cleared first")
        imp_rva, imp_size, imp_at = self.data_directory(1)
        off = self.offset_of(self.image_base + imp_rva)
        if off is None:
            raise ValueError("import directory is not backed by file bytes")
        old = []
        while True:
            fields = struct.unpack_from("<IIIII", self.d, off + len(old) * 20)
            if not any(fields):
                break
            old.append(fields)
        if not old:
            raise ValueError("no import descriptors found")

        dll_b = dll.encode() + b"\0"
        func_b = func.encode() + b"\0"
        n_desc = len(old) + 2                       # the originals, ours, and the null terminator
        desc_len = n_desc * 20
        ilt_at = desc_len                           # two u32: our one import, then the terminator
        iat_at = ilt_at + 8
        hint_at = iat_at + 8
        name_at = hint_at + align(2 + len(func_b), 2)
        total = name_at + len(dll_b)

        base_va = self.reserve(total, materialise=True, label="import descriptors")
        where = ARENA_DATA
        base_rva = base_va - self.image_base
        o = self.offset_of(base_va)
        for i, fields in enumerate(old):            # copy the originals verbatim
            struct.pack_into("<IIIII", self.d, o + i * 20, *fields)
        struct.pack_into("<IIIII", self.d, o + len(old) * 20,
                         base_rva + ilt_at, 0, 0, base_rva + name_at, base_rva + iat_at)
        struct.pack_into("<IIIII", self.d, o + (len(old) + 1) * 20, 0, 0, 0, 0, 0)
        struct.pack_into("<II", self.d, o + ilt_at, base_rva + hint_at, 0)
        struct.pack_into("<II", self.d, o + iat_at, base_rva + hint_at, 0)
        struct.pack_into("<H", self.d, o + hint_at, 0)
        self.d[o + hint_at + 2:o + hint_at + 2 + len(func_b)] = func_b
        self.d[o + name_at:o + name_at + len(dll_b)] = dll_b
        struct.pack_into("<II", self.d, imp_at, base_rva, desc_len)
        return dict(section=where, va=base_va, descriptors=len(old) + 1, bytes=total,
                    old_directory=(imp_rva, imp_size), new_directory=(base_rva, desc_len))

    def append_bss_section(self, name: str, size: int, materialise: bool = False,
                           execute: bool = False):
        """Append a section for a relocated static object, and return its virtual address.

        This is how a recipe moves a large object off a fixed static slot without needing a code cave or
        an allocator -- the object's address is an immediate in a handful of instructions, so it can just
        be pointed somewhere with room.

        `materialise` decides whether the section carries real bytes on disk:

          False -- uninitialised (BSS): SizeOfRawData = 0, the loader is expected to zero-fill. Compact,
                   and what a compiler emits for .bss. NOT SAFE EVERYWHERE: measured 2026-09-13, a
                   virtual-only section produced a deterministic fault on the first write into the
                   relocated object under Wine (MobHatchery -> mh_Load -> l_AllocZ), while the same
                   binary was fine on the paths that never touched it.
          True  -- zero bytes written to the file, SizeOfRawData set. Costs file size (a 103MB object
                   makes a 108MB exe) and buys a section the loader has no choice but to map."""
        if len(name.encode()) > 8:
            raise ValueError("section name must be 8 bytes or fewer")
        hdr_end = self.sec_table + 40 * self.n_sections
        first_raw = min((s["rawptr"] for s in self.sections if s["rawptr"]), default=0)
        if hdr_end + 40 > first_raw:
            raise ValueError("no room in the section table for another header")

        rva = align(self.size_of_image, self.section_alignment)
        vsize = align(size, self.section_alignment)
        rawsize, rawptr, kind = 0, 0, IMAGE_SCN_CNT_UNINITIALIZED_DATA
        if materialise:
            rawptr = align(len(self.d), self.file_alignment)
            self.d.extend(bytes(rawptr - len(self.d)))     # pad to file alignment
            rawsize = align(size, self.file_alignment)
            self.d.extend(bytes(rawsize))
            kind = IMAGE_SCN_CNT_INITIALIZED_DATA
        struct.pack_into("<8s", self.d, hdr_end, name.encode())
        struct.pack_into("<IIII", self.d, hdr_end + 8, vsize, rva, rawsize, rawptr)
        flags = kind | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
        if execute:
            flags |= IMAGE_SCN_MEM_EXECUTE
        struct.pack_into("<IIHHI", self.d, hdr_end + 24, 0, 0, 0, 0, flags)
        self.n_sections += 1
        struct.pack_into("<H", self.d, self.e_lfanew + 4 + 2, self.n_sections)
        self.size_of_image = rva + vsize
        struct.pack_into("<I", self.d, self.size_of_image_off, self.size_of_image)
        self.sections.append(dict(name=name, off=hdr_end, vsize=vsize, va=rva,
                                  rawsize=rawsize, rawptr=rawptr))
        return self.image_base + rva

    def reserve(self, size: int, materialise: bool = False, execute: bool = False, label: str = ""):
        """Carve `size` bytes out of a SHARED arena section and return their virtual address.

        Every recipe that needed somewhere to put a relocated object used to append a section of its own.
        That is one PE section header each, and the section table grows towards the first section's raw
        data: after eight of them the table was exactly full at 0x400, where .text begins, and the ninth
        recipe could not be applied at all. Nothing about those recipes wanted a whole section - they
        wanted a REGION of a given size at a known address.

        TWO arenas, because page protection is a property of the section and code caves need execute.
        Both are created together, on first use of either, and in this order for a reason:

            .zarenax   executable, FIXED SIZE. Code caves are tiny (0x1000 each, three of them today).
            .zarena    data, GROWS. Always the last section in the image, so extending it can never
                       overlap anything.

        Creating them in the other order - or creating the exec arena later, on demand - leaves the data
        arena with a section after it, and then it cannot grow. That is exactly what happened on the
        first attempt, at recipe 11 of 12.

        Each arena starts with a 16-byte header holding how much of it is in use, so a CHAIN of separate
        apply.py runs can keep allocating without being told what came before. Regions are 16-byte
        aligned and never overlap, and the arena only ever grows at its end, so an address handed out by
        an earlier recipe stays valid."""
        self._ensure_arenas(size if not execute else 0)
        name = ARENA_EXEC if execute else ARENA_DATA
        sec = next(s for s in self.sections if s["name"] == name)

        used = self._arena_used(sec)
        off = align(used, 16)
        need = off + size

        if need > sec["vsize"]:
            if execute:
                raise ValueError(
                    "%s is full: %d bytes reserved, %d needed. Raise ARENA_EXEC_SIZE and rebuild the "
                    "chain from the stock exe - it cannot be grown in place, because the data arena "
                    "sits after it." % (name, sec["vsize"], need))
            self._grow_data_arena(sec, need, materialise or bool(sec["rawsize"]))

        self._arena_set_used(sec, need)
        self._arena_record(label, off, size, execute)
        base = self.image_base + sec["va"] + off
        self._arena_note(label, base, size, name, fresh=False)
        return base

    def _ensure_arenas(self, data_hint: int):
        """Create both arenas, exec first, if neither exists yet."""
        have_x = any(s["name"] == ARENA_EXEC for s in self.sections)
        have_d = any(s["name"] == ARENA_DATA for s in self.sections)
        if have_x and have_d:
            return
        if have_x != have_d:
            raise ValueError("only one arena exists; the image was built by an older apply.py - rebuild "
                             "the chain from the stock exe")
        self.append_bss_section(ARENA_EXEC, ARENA_EXEC_SIZE, materialise=True, execute=True)
        self._arena_init(next(s for s in self.sections if s["name"] == ARENA_EXEC))
        self.append_bss_section(ARENA_DATA, max(data_hint, 0) + ARENA_HEADER, materialise=True)
        self._arena_init(next(s for s in self.sections if s["name"] == ARENA_DATA))
        # Both arenas' directories live in the data arena, so the exec arena's high-water mark starts
        # after its own small header and its regions are recorded here.
        self._arena_set_used(next(s for s in self.sections if s["name"] == ARENA_DATA), ARENA_HEADER)

    def _grow_data_arena(self, sec, need: int, materialise: bool):
        if any(s["va"] > sec["va"] for s in self.sections):
            raise ValueError("%s is not the last section in memory; cannot grow it" % sec["name"])
        if sec["rawsize"] and sec["rawptr"] + sec["rawsize"] != len(self.d):
            raise ValueError("%s's raw data is not at the end of the file; cannot grow it" % sec["name"])

        new_rawsize = sec["rawsize"]
        if materialise:
            # Once an arena carries real bytes it must carry them all the way to its end: a region past
            # SizeOfRawData reads as the loader's zero-fill, and offset_of() would rightly refuse to back
            # it with file bytes.
            if not sec["rawptr"]:
                sec["rawptr"] = align(len(self.d), self.file_alignment)
                self.d.extend(bytes(sec["rawptr"] - len(self.d)))
                struct.pack_into("<I", self.d, sec["off"] + 20, sec["rawptr"])
            new_rawsize = align(need, self.file_alignment)
            want = sec["rawptr"] + new_rawsize
            if want > len(self.d):
                self.d.extend(bytes(want - len(self.d)))

        struct.pack_into("<I", self.d, sec["off"] + 8, need)            # VirtualSize
        struct.pack_into("<I", self.d, sec["off"] + 16, new_rawsize)    # SizeOfRawData
        sec["vsize"], sec["rawsize"] = need, new_rawsize
        self.size_of_image = max(self.size_of_image,
                                 align(sec["va"] + need, self.section_alignment))
        struct.pack_into("<I", self.d, self.size_of_image_off, self.size_of_image)

    # The arena header: a magic so a stray pointer into it is recognisable in a dump, and the high-water
    # mark so the next apply.py run knows where to continue.
    def _arena_init(self, sec):
        o = sec["rawptr"]
        self.d[o:o + 8] = ARENA_MAGIC
        struct.pack_into("<II", self.d, o + 8, ARENA_DIR_AT if sec["name"] == ARENA_EXEC else ARENA_HEADER,
                         sec["vsize"])

    def _dir_base(self):
        sec = next(s for s in self.sections if s["name"] == ARENA_DATA)
        return sec["rawptr"] + ARENA_DIR_AT

    def _arena_record(self, label, off, size, execute):
        """Add one region to the directory. A repeated label replaces its entry, so re-running a recipe
        over an image does not leave a stale duplicate."""
        base = self._dir_base()
        key = (label or "?").encode("latin-1")[:19]
        free = None
        for i in range(ARENA_DIR_MAX):
            at = base + i * ARENA_DIR_ENTRY
            name = bytes(self.d[at:at + 20]).rstrip(b"\0")
            if not name and free is None:
                free = at
            if name == key:
                free = at
                break
        if free is None:
            raise ValueError("arena directory is full (%d regions)" % ARENA_DIR_MAX)
        self.d[free:free + 20] = key.ljust(20, b"\0")
        struct.pack_into("<III", self.d, free + 20, off, size, ARENA_FLAG_EXEC if execute else 0)

    def arena_lookup(self, label):
        """(virtual address, size) of a region a recipe reserved earlier, or None."""
        try:
            base = self._dir_base()
        except StopIteration:
            return None
        key = (label or "?").encode("latin-1")[:19]
        for i in range(ARENA_DIR_MAX):
            at = base + i * ARENA_DIR_ENTRY
            name = bytes(self.d[at:at + 20]).rstrip(b"\0")
            if name != key:
                continue
            off, size, flags = struct.unpack_from("<III", self.d, at + 20)
            which = ARENA_EXEC if flags & ARENA_FLAG_EXEC else ARENA_DATA
            sec = next((s for s in self.sections if s["name"] == which), None)
            if not sec:
                return None
            return self.image_base + sec["va"] + off, size
        return None

    def _arena_used(self, sec):
        o = sec["rawptr"]
        if bytes(self.d[o:o + 8]) != ARENA_MAGIC:
            raise ValueError("%s has no arena header - the image was not built by this apply.py"
                             % sec["name"])
        return struct.unpack_from("<I", self.d, o + 8)[0]

    def _arena_set_used(self, sec, used):
        struct.pack_into("<I", self.d, sec["rawptr"] + 8, used)

    def _arena_note(self, label, base, size, name, fresh):
        self.arena_log.append(dict(label=label, va=base, size=size, section=name, fresh=fresh))

    def make_header_room(self):
        """Push every section's raw data down by one file-alignment block so another section header fits.

        The section table grows towards the first section's raw data, and this image is exactly full: 13
        headers end at 0x400, which is where .text begins. Squeezing the new data into a neighbouring
        section instead LOOKS like it works and does not - tried first, and it produced a .qend whose
        grown virtual range overlapped .npct's start, so two sections claimed one RVA and the loader
        mapped the BSS over the import table. pefile could not resolve the imports either, which is how
        it was caught.

        Only file offsets move. Every RVA, and therefore every address in the PDB and in every recipe,
        is untouched."""
        step = self.file_alignment
        first_raw = min((s["rawptr"] for s in self.sections if s["rawptr"]), default=0)
        if not first_raw:
            raise ValueError("no section has raw data; nothing to move")
        self.d[first_raw:first_raw] = bytes(step)
        for s in self.sections:
            if s["rawptr"]:
                s["rawptr"] += step
                struct.pack_into("<I", self.d, s["off"] + 20, s["rawptr"])
        size_of_headers_off = self.e_lfanew + 24 + 60
        soh = struct.unpack_from("<I", self.d, size_of_headers_off)[0]
        struct.pack_into("<I", self.d, size_of_headers_off, soh + step)
        # Any data directory pointing at a file-backed structure still resolves: directories are RVAs.
        return step

def align(v, a):
    return (v + a - 1) & ~(a - 1)


# -- recipe expressions ----------------------------------------------------------------------------
# Deliberately NOT eval(): a recipe is data, and data from a file should not be able to run code.
_TOKEN = re.compile(r"\s*(0x[0-9a-fA-F]+|\d+|[A-Za-z_@][A-Za-z0-9_@]*|[()+\-*/])")


def evaluate(expr, env):
    """Arithmetic over recipe params and names. Integers only -- these are sizes and addresses."""
    if isinstance(expr, int):
        return expr
    toks, pos = [], 0
    while pos < len(expr):
        m = _TOKEN.match(expr, pos)
        if not m:
            raise ValueError(f"bad expression {expr!r} at {pos}")
        toks.append(m.group(1))
        pos = m.end()

    def atom(i):
        t = toks[i]
        if t == "(":
            v, i = expr_(i + 1)
            if toks[i] != ")":
                raise ValueError("unbalanced (")
            return v, i + 1
        if t == "-":
            v, i = atom(i + 1)
            return -v, i
        if t.startswith("0x"):
            return int(t, 16), i + 1
        if t.isdigit():
            return int(t), i + 1
        if t not in env:
            raise ValueError(f"unknown name {t!r} in {expr!r}")
        return env[t], i + 1

    def term(i):
        v, i = atom(i)
        while i < len(toks) and toks[i] in "*/":
            op = toks[i]
            r, i = atom(i + 1)
            v = v * r if op == "*" else v // r
        return v, i

    def expr_(i):
        v, i = term(i)
        while i < len(toks) and toks[i] in "+-":
            op = toks[i]
            r, i = term(i + 1)
            v = v + r if op == "+" else v - r
        return v, i

    v, i = expr_(0)
    if i != len(toks):
        raise ValueError(f"trailing tokens in {expr!r}")
    return v


def load_recipe(path, overrides):
    with open(path, encoding="utf-8") as f:
        r = json.load(f)
    for k, v in overrides.items():
        if k not in r.get("params", {}):
            raise SystemExit(f"--set {k}: not a parameter of this recipe "
                             f"(has: {', '.join(r.get('params', {}))})")
        r["params"][k] = v
    return r


def main():
    ap = argparse.ArgumentParser(description="Apply a declarative binary-patch recipe to a PE32 image.")
    ap.add_argument("recipe")
    ap.add_argument("--exe", required=True, help="input image; opened READ-ONLY")
    ap.add_argument("--out", help="output image (required unless --dry-run/--verify)")
    ap.add_argument("--dry-run", action="store_true", help="validate every site and print the plan")
    ap.add_argument("--verify", metavar="IMAGE", help="check an already-patched image instead of writing")
    ap.add_argument("--set", action="append", default=[], metavar="K=V",
                    help="override a recipe parameter, e.g. --set groups=32768")
    ap.add_argument("--allow-hash-mismatch", action="store_true",
                    help="proceed even if the input does not match the recipe's recorded hash")
    a = ap.parse_args()

    overrides = {}
    for kv in a.set:
        k, _, v = kv.partition("=")
        overrides[k.strip()] = int(v, 0)
    r = load_recipe(a.recipe, overrides)

    src = open(a.exe, "rb").read()
    digest = hashlib.sha256(src).hexdigest()
    want = r.get("target", {}).get("sha256")
    if want and digest != want:
        msg = (f"input sha256 {digest}\n  recipe expects {want}\n"
               "  This recipe was written against a specific build. Every offset in it was read out of "
               "THAT binary; applying it to another is how you corrupt one instruction and find out weeks "
               "later.")
        if not a.allow_hash_mismatch:
            raise SystemExit("REFUSING: " + msg)
        print("WARNING: " + msg, file=sys.stderr)

    pe = Pe(bytearray(src))
    # consts/params may be written as hex STRINGS ("0x19B8000") -- decimal transcription of an address
    # read out of a disassembler is a reliable way to get it wrong, so the recipe is allowed to keep the
    # hex it was read as. Resolve to ints once, here, so edits only ever see numbers.
    env = {}
    for k, v in list(r.get("consts", {}).items()) + list(r.get("params", {}).items()):
        env[k] = evaluate(v, env) if isinstance(v, str) else v

    for name, limit in (r.get("limits") or {}).items():
        val = env.get(name, 0)
        if "max" in limit:
            cap = evaluate(limit["max"], env)
            if val > cap:
                raise SystemExit(f"REFUSING: {name}={val} exceeds {cap} -- {limit['why']}")
        if "multiple_of" in limit and val % limit["multiple_of"]:
            raise SystemExit(f"REFUSING: {name}={val} is not a multiple of {limit['multiple_of']} "
                             f"-- {limit['why']}")

    print(f"recipe : {r['name']}  -- {r.get('summary','')}")
    print(f"input  : {a.exe}  ({len(src):,} bytes, sha256 {digest[:16]}...)")
    print(f"params : " + ", ".join(f"{k}={v}" for k, v in r.get("params", {}).items()))

    # The new section has to exist before edits resolve, because edits may reference its address.
    newbase = None
    ns = r.get("new_section")
    if ns:
        size = evaluate(ns["size"], env)
        if a.verify:
            tgt = Pe(bytearray(open(a.verify, "rb").read()))
            # Regions share the arenas, so a region's address depends on which recipes ran before it.
            # The image records it: read it back rather than recomputing something that cannot be known
            # from this recipe alone.
            found = tgt.arena_lookup(ns["name"])
            if not found:
                raise SystemExit(f"VERIFY FAILED: {a.verify} has no arena region named {ns['name']}")
            newbase, got_size = found
            if got_size < size:
                raise SystemExit(f"VERIFY FAILED: region {ns['name']} is {got_size:,} bytes, "
                                 f"recipe wants {size:,}")
            print(f"region : {ns['name']} at VA 0x{newbase:08X} ({got_size:,} bytes, from the "
                  f"arena directory)")
        else:
            newbase = pe.reserve(size, bool(ns.get("materialise")), bool(ns.get("execute")),
                                 label=ns["name"])
            note = pe.arena_log[-1]
            print(f"region : {ns['name']} at VA 0x{newbase:08X}, {size:,} bytes in {note['section']}"
                  f"{' (new)' if note['fresh'] else ''}; SizeOfImage -> 0x{pe.size_of_image:08X}")
        env["@newbase"] = newbase

    # -- an extra import, so the zone can be extended in C++ instead of hand-assembled bytes -----------
    ai = r.get("add_import")
    if ai:
        if a.dry_run or a.verify:
            print(f"add_import: {ai['dll']}!{ai['function']} into a new {ai.get('section', '.zhook')} section")
        else:
            info = pe.add_import(ai["dll"], ai["function"], ai.get("section", ".zhook"))
            print(f"add_import: {ai['dll']}!{ai['function']} -> section {info['section']} at "
                  f"0x{info['va']:08X} ({info['bytes']} bytes, {info['descriptors']} descriptors)")
            print(f"  import directory RVA 0x{info['old_directory'][0]:08X} size 0x{info['old_directory'][1]:X}"
                  f"  ->  RVA 0x{info['new_directory'][0]:08X} size 0x{info['new_directory'][1]:X}")

    # -- validate every site BEFORE touching anything -----------------------------------------------
    reader = Pe(bytearray(open(a.verify, "rb").read())) if a.verify else pe
    plan, problems = [], []
    for e in r["edits"]:
        va = evaluate(e["at"], env)
        off = reader.offset_of(va)
        if off is None:
            problems.append(f"  0x{va:08X}: not backed by file bytes")
            continue
        # "width": 4 (default) | 2 | 1 -- imm8/imm16 operands and single opcode bytes are edited at their own
        # width, so a recipe never has to spell out the neighbouring bytes of an instruction it does not touch
        width_ = int(e.get("width", 4))
        fmt = {1: "<B", 2: "<H", 4: "<I"}[width_]
        mask = (1 << (8 * width_)) - 1
        cur = struct.unpack_from(fmt, reader.d, off)[0]
        expect = evaluate(e["expect"], env) & mask
        write = evaluate(e["write"], env)
        if write < 0 or write > mask:
            problems.append(f"  0x{va:08X}: value 0x{write:X} does not fit in {width_} byte(s)  [{e['why']}]")
            continue
        target = write if a.verify else expect
        ok = cur == target
        if not ok:
            problems.append(f"  0x{va:08X}: found 0x{cur:0{2*width_}X}, expected 0x{target:0{2*width_}X}  [{e['why']}]")
        plan.append((va, off, cur, write, e["why"], ok, fmt))

    if problems:
        head = "VERIFY FAILED" if a.verify else "REFUSING TO PATCH"
        raise SystemExit(f"{head}: {len(problems)} site(s) did not match:\n" + "\n".join(problems))

    width = max((len(e["why"]) for e in r["edits"]), default=0)   # a recipe may be all section/import work
    for va, off, cur, write, why, _, fmt in plan:
        print(f"  {why:<{width}}  VA 0x{va:08X}  0x{cur:08X} -> 0x{write:08X}  ({struct.calcsize(fmt)} B)")

    # -- code blobs ---------------------------------------------------------------------------------
    # A recipe sometimes needs to place INSTRUCTIONS, not just change a constant -- e.g. a saturating
    # wrapper around a CRT helper. Each blob is literal hex plus computed fields, so the recipe stays
    # readable and relative addresses are worked out at apply time instead of by hand.
    blobs = []
    for c in r.get("code", []):
        at = evaluate(c["at"], env)
        out = bytearray()
        for piece in c["emit"]:
            if isinstance(piece, str):
                out += bytes.fromhex(piece.replace(" ", ""))
            elif "u32" in piece:
                out += struct.pack("<I", evaluate(piece["u32"], env) & 0xFFFFFFFF)
            elif "rel32" in piece:
                # x86 rel32 is relative to the address of the NEXT instruction, i.e. just past this field
                out += struct.pack("<i", evaluate(piece["rel32"], env) - (at + len(out) + 4))
            else:
                raise SystemExit(f"unknown emit piece {piece!r}")
        blobs.append((at, bytes(out), c["why"]))

    for at, out, why in blobs:
        print(f"  {why}\n    {len(out)} bytes at VA 0x{at:08X}: {out.hex()}")

    if a.verify:
        print(f"\nVERIFIED: all {len(plan)} sites hold their patched values, section present.")
        return
    if a.dry_run:
        print(f"\nDRY RUN: {len(plan)} sites validated, nothing written.")
        return
    if not a.out:
        raise SystemExit("--out is required unless --dry-run or --verify")

    for va, off, cur, write, why, _, fmt in plan:
        struct.pack_into(fmt, pe.d, off, write)

    for at, out, why in blobs:
        off = pe.offset_of(at)
        if off is None:
            raise SystemExit(f"code blob at 0x{at:08X} is not backed by file bytes -- the section it "
                             f'lands in needs "materialise": true')
        pe.d[off:off + len(out)] = out

    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "wb") as f:
        f.write(pe.d)
    out_digest = hashlib.sha256(bytes(pe.d)).hexdigest()
    print(f"\nwrote {a.out} ({len(pe.d):,} bytes, sha256 {out_digest[:16]}...)")
    print(f"re-check with:  python {os.path.basename(__file__)} {a.recipe} --exe {a.exe} --verify {a.out}")


if __name__ == "__main__":
    main()
