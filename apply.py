#!/usr/bin/env python
"""Apply a declarative binary-patch recipe to a PE32 image.

    python apply.py recipes/mob-spawn-group-cap.json --exe Z:/ServerSource/Zone00/Zone.exe --out build/Zone.exe
    python apply.py recipes/mob-spawn-group-cap.json --exe ... --dry-run
    python apply.py recipes/mob-spawn-group-cap.json --exe ... --verify build/Zone.exe

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

SECTION_ALIGNMENT_FALLBACK = 0x1000
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
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

    def append_bss_section(self, name: str, size: int):
        """Append an uninitialised (BSS) section: virtual bytes the loader zero-fills, no file bytes.

        Returns its virtual address. This is how the recipe gets a large object off a fixed static slot
        without needing a code cave or an allocator -- the object's address is an immediate in exactly
        three instructions, so it can simply be pointed somewhere with room."""
        if len(name.encode()) > 8:
            raise ValueError("section name must be 8 bytes or fewer")
        hdr_end = self.sec_table + 40 * self.n_sections
        first_raw = min((s["rawptr"] for s in self.sections if s["rawptr"]), default=0)
        if hdr_end + 40 > first_raw:
            raise ValueError("no room in the section table for another header")

        rva = align(self.size_of_image, self.section_alignment)
        vsize = align(size, self.section_alignment)
        struct.pack_into("<8s", self.d, hdr_end, name.encode())
        struct.pack_into("<IIII", self.d, hdr_end + 8, vsize, rva, 0, 0)
        struct.pack_into("<IIHHI", self.d, hdr_end + 24, 0, 0, 0, 0,
                         IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)
        self.n_sections += 1
        struct.pack_into("<H", self.d, self.e_lfanew + 4 + 2, self.n_sections)
        self.size_of_image = rva + vsize
        struct.pack_into("<I", self.d, self.size_of_image_off, self.size_of_image)
        self.sections.append(dict(name=name, off=hdr_end, vsize=vsize, va=rva, rawsize=0, rawptr=0))
        return self.image_base + rva


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
        cap = evaluate(limit["max"], env)
        if env.get(name, 0) > cap:
            raise SystemExit(f"REFUSING: {name}={env.get(name)} exceeds {cap} -- {limit['why']}")

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
            found = [s for s in tgt.sections if s["name"] == ns["name"]]
            if not found:
                raise SystemExit(f"VERIFY FAILED: no section named {ns['name']} in {a.verify}")
            newbase = tgt.image_base + found[0]["va"]
            print(f"section: {ns['name']} present at VA 0x{newbase:08X} "
                  f"({found[0]['vsize']:,} bytes virtual)")
        else:
            newbase = pe.append_bss_section(ns["name"], size)
            print(f"section: +{ns['name']} at VA 0x{newbase:08X}, {align(size, pe.section_alignment):,} "
                  f"bytes virtual (0 on disk); SizeOfImage -> 0x{pe.size_of_image:08X}")
        env["@newbase"] = newbase

    # -- validate every site BEFORE touching anything -----------------------------------------------
    reader = Pe(bytearray(open(a.verify, "rb").read())) if a.verify else pe
    plan, problems = [], []
    for e in r["edits"]:
        va = evaluate(e["at"], env)
        off = reader.offset_of(va)
        if off is None:
            problems.append(f"  0x{va:08X}: not backed by file bytes")
            continue
        cur = struct.unpack_from("<I", reader.d, off)[0]
        expect = evaluate(e["expect"], env)
        write = evaluate(e["write"], env)
        target = write if a.verify else expect
        ok = cur == target
        if not ok:
            problems.append(f"  0x{va:08X}: found 0x{cur:08X}, expected 0x{target:08X}  [{e['why']}]")
        plan.append((va, off, cur, write, e["why"], ok))

    if problems:
        head = "VERIFY FAILED" if a.verify else "REFUSING TO PATCH"
        raise SystemExit(f"{head}: {len(problems)} site(s) did not match:\n" + "\n".join(problems))

    width = max(len(e["why"]) for e in r["edits"])
    for va, off, cur, write, why, _ in plan:
        print(f"  {why:<{width}}  VA 0x{va:08X}  0x{cur:08X} -> 0x{write:08X}")

    if a.verify:
        print(f"\nVERIFIED: all {len(plan)} sites hold their patched values, section present.")
        return
    if a.dry_run:
        print(f"\nDRY RUN: {len(plan)} sites validated, nothing written.")
        return
    if not a.out:
        raise SystemExit("--out is required unless --dry-run or --verify")

    for va, off, cur, write, why, _ in plan:
        struct.pack_into("<I", pe.d, off, write)

    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "wb") as f:
        f.write(pe.d)
    out_digest = hashlib.sha256(bytes(pe.d)).hexdigest()
    print(f"\nwrote {a.out} ({len(pe.d):,} bytes, sha256 {out_digest[:16]}...)")
    print(f"re-check with:  python {os.path.basename(__file__)} {a.recipe} --exe {a.exe} --verify {a.out}")


if __name__ == "__main__":
    main()
