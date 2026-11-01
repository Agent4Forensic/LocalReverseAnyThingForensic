#!/usr/bin/env python3
"""Fixed entry of the sw-analyst/emu image (ADR-0005 stage 2): one routine of a file in a simulated CPU, never as a process.

stdin:  u32le header length, JSON header (numbers and fixed words, built by gateway/container_tools.py), then the file.
stdout: one JSON object. A refusal is {"error": "..."} with exit code 0, so the same input gives the same answer.
There is no operating system here: imports stop the run with the API name, and any other unmapped access stops it with the
fault address. Nothing from the file is ever interpreted as a command for this script.
"""
import base64
import hashlib
import json
import struct
import sys
import time

import unicorn
from unicorn import arm64_const as a64
from unicorn import arm_const as a32
from unicorn import x86_const as x86

MAX_INPUT = 67108865 + 65536
MAX_MAPPED = 256 * 1024 * 1024
MAX_SEGMENTS = 128
MAX_IMPORTS = 4096
MAX_INSTRUCTIONS = 20_000_000
TIMEOUT_S = 30
MAX_REGION_BYTES = 1024 * 1024
MAX_REGIONS = 32
MAX_WRITTEN_BLOCKS = 1 << 20      # 16 MiB in blocks of 16 bytes
PAGE = 0x1000
INPUT_BASE = 0x60000000
INPUT_MAX = 16 * 1024 * 1024
STUB_BASE = 0x70000000
SENTINEL = 0x7DFFF000
STACK_BASE = 0x7E000000
STACK_SIZE = 1024 * 1024
RAW_BASE = 0x10000
ELF_PIE_BASE = 0x100000           # the base Ghidra shows for shared objects, so its addresses work here
ARCHES = {"x86": (unicorn.UC_ARCH_X86, unicorn.UC_MODE_32), "x64": (unicorn.UC_ARCH_X86, unicorn.UC_MODE_64),
          "arm": (unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM), "arm64": (unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)}
REGS = {"x86": {n: getattr(x86, "UC_X86_REG_E" + n[1:].upper()) for n in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")},
        "x64": {n: getattr(x86, "UC_X86_REG_" + n.upper()) for n in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                                                                     "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")},
        "arm": {f"r{i}": getattr(a32, f"UC_ARM_REG_R{i}") for i in range(13)} | {"sp": a32.UC_ARM_REG_SP, "lr": a32.UC_ARM_REG_LR},
        "arm64": {f"x{i}": getattr(a64, f"UC_ARM64_REG_X{i}") for i in range(29)} | {"sp": a64.UC_ARM64_REG_SP, "lr": a64.UC_ARM64_REG_LR}}
PC = {"x86": x86.UC_X86_REG_EIP, "x64": x86.UC_X86_REG_RIP, "arm": a32.UC_ARM_REG_PC, "arm64": a64.UC_ARM64_REG_PC}
RET = {"x86": "eax", "x64": "rax", "arm": "r0", "arm64": "x0"}


class Refuse(Exception):
    """The request cannot run on this file; the message goes to the model and must not quote the file."""


def _u(fmt, data, off):
    try:
        return struct.unpack_from(fmt, data, off)
    except struct.error:
        raise Refuse("file is truncated inside its headers") from None


def _cstr(data, off, limit=128):
    end = data.find(b"\0", off, off + limit)
    raw = data[off:end if end >= 0 else off + limit]
    return "".join(chr(c) if 32 <= c < 127 else "?" for c in raw)


def load_pe(f):
    e_lfanew = _u("<I", f, 0x3C)[0]
    if f[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise Refuse("MZ file without a PE header")
    machine, nsec, _, _, _, opt_size, _ = _u("<HHIIIHH", f, e_lfanew + 4)
    opt = e_lfanew + 24
    magic = _u("<H", f, opt)[0]
    if machine == 0x14C and magic == 0x10B:
        arch, base, dirs = "x86", _u("<I", f, opt + 28)[0], opt + 96
    elif machine == 0x8664 and magic == 0x20B:
        arch, base, dirs = "x64", _u("<Q", f, opt + 24)[0], opt + 112
    else:
        raise Refuse("only x86 and x64 PE files can be emulated")
    size_image, size_headers = _u("<II", f, opt + 56)
    if not 0 < size_image <= MAX_MAPPED:
        raise Refuse("image size is outside the emulation limit")
    image = bytearray(size_image)
    head = f[:min(size_headers, size_image, len(f))]
    image[:len(head)] = head
    if nsec > 96:
        raise Refuse("too many sections")
    for i in range(nsec):
        vsize, rva, rsize, rptr = _u("<IIII", f, opt + opt_size + i * 40 + 8)
        if rva >= size_image:
            continue
        chunk = f[rptr:rptr + min(rsize, vsize or rsize, size_image - rva)]
        image[rva:rva + len(chunk)] = chunk
    imports = _pe_imports(image, dirs, arch, base)
    return {"format": "pe", "arch": arch, "load_base": base, "segments": [(base, bytes(image))], "imports": imports}, image


def _pe_imports(image, dirs, arch, base):
    """Returns {slot rva: name} and leaves the slots unfilled; run() writes the stub addresses."""
    rva = _u("<I", image, dirs + 8)[0]
    width, flag = (8, 1 << 63) if arch == "x64" else (4, 1 << 31)
    fmt = "<Q" if width == 8 else "<I"
    out = {}
    for d in range(256):
        desc = rva + d * 20
        if not rva or desc + 20 > len(image):
            break
        ilt, _, _, name_rva, iat = _u("<IIIII", image, desc)
        if not (ilt or iat):
            break
        dll = _cstr(image, name_rva) if name_rva < len(image) else "?"
        for n in range(MAX_IMPORTS):
            lookup, slot = (ilt or iat) + n * width, iat + n * width
            if lookup + width > len(image) or slot + width > len(image) or len(out) >= MAX_IMPORTS:
                break
            thunk = _u(fmt, image, lookup)[0]
            if not thunk:
                break
            func = f"#{thunk & 0xFFFF}" if thunk & flag else (_cstr(image, (thunk & 0x7FFFFFFF) + 2)
                                                              if (thunk & 0x7FFFFFFF) + 2 < len(image) else "?")
            out[slot] = f"{dll}!{func}"
    return {"rvas": out, "base": base, "fmt": fmt}


def load_elf(f):
    if f[4] not in (1, 2) or f[5] != 1:
        raise Refuse("only little-endian ELF files can be emulated")
    is64 = f[4] == 2
    etype, machine = _u("<HH", f, 16)
    arch = {(3, False): "x86", (62, True): "x64", (40, False): "arm", (183, True): "arm64"}.get((machine, is64))
    if not arch:
        raise Refuse("only x86, x64, ARM and ARM64 ELF files can be emulated")
    phoff, phent, phnum = (_u("<Q", f, 32)[0], *_u("<HH", f, 54)) if is64 else (_u("<I", f, 28)[0], *_u("<HH", f, 42))
    if phnum > MAX_SEGMENTS:
        raise Refuse("too many ELF segments")
    base = ELF_PIE_BASE if etype == 3 else 0
    segments = []
    for i in range(phnum):
        p = phoff + i * phent
        if is64:
            ptype, _, off, vaddr, _, filesz, memsz, _ = _u("<IIQQQQQQ", f, p)
        else:
            ptype, off, vaddr, _, filesz, memsz, _, _ = _u("<IIIIIIII", f, p)
        if ptype != 1 or not memsz:
            continue
        if memsz > MAX_MAPPED:
            raise Refuse("ELF segment is outside the emulation limit")
        segments.append((base + vaddr, f[off:off + min(filesz, memsz)].ljust(memsz, b"\0")))
    if not segments:
        raise Refuse("ELF file without loadable segments")
    return {"format": "elf", "arch": arch, "load_base": base, "segments": segments, "imports": None}, None


def load(f, arch):
    if arch != "auto":
        if arch not in ARCHES:
            raise Refuse("unknown arch")
        return {"format": "raw", "arch": arch, "load_base": RAW_BASE, "segments": [(RAW_BASE, f)], "imports": None}, None
    if f[:2] == b"MZ":
        return load_pe(f)
    if f[:4] == b"\x7fELF" and len(f) >= 52:
        return load_elf(f)
    raise Refuse("not a PE or ELF file: name the arch (x86, x64, arm, arm64) to treat the bytes as raw code")


def _merge(ranges):
    out = []
    for lo, hi in sorted(ranges):
        if out and lo <= out[-1][1]:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return out


def _set_call(uc, info, arch, args, ret):
    regs = REGS[arch]
    sp = STACK_BASE + STACK_SIZE - 0x1000
    if arch == "x86":
        for value in reversed(args):
            sp -= 4
            uc.mem_write(sp, struct.pack("<I", value & 0xFFFFFFFF))
        sp -= 4
        uc.mem_write(sp, struct.pack("<I", ret))
        uc.reg_write(regs["esp"], sp)
    elif arch == "x64":
        names = ("rcx", "rdx", "r8", "r9") if info["format"] == "pe" else ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
        sp -= 0x108                    # keeps rsp 8 off a 16 byte boundary, as after a call; leaves shadow space
        for i, value in enumerate(args[len(names):]):
            uc.mem_write(sp + 0x28 + 8 * i, struct.pack("<Q", value & (2 ** 64 - 1)))
        for name, value in zip(names, args):
            uc.reg_write(regs[name], value & (2 ** 64 - 1))
        uc.mem_write(sp, struct.pack("<Q", ret))
        uc.reg_write(regs["rsp"], sp)
    elif arch == "arm":
        if len(args) > 4:
            raise Refuse("ARM calls take at most 4 arguments here")
        for i, value in enumerate(args):
            uc.reg_write(regs[f"r{i}"], value & 0xFFFFFFFF)
        uc.reg_write(regs["lr"], ret)
        uc.reg_write(regs["sp"], sp)
    else:
        for i, value in enumerate(args):
            uc.reg_write(regs[f"x{i}"], value & (2 ** 64 - 1))
        uc.reg_write(regs["lr"], ret)
        uc.reg_write(regs["sp"], sp)


def _kind(addr, info):
    if STACK_BASE <= addr < STACK_BASE + STACK_SIZE:
        return "stack"
    if INPUT_BASE <= addr < INPUT_BASE + INPUT_MAX:
        return "input"
    return "image" if any(va <= addr < va + len(d) for va, d in info["segments"]) else "other"


def emulate(header, f):
    start, end = header["start"], header.get("end")
    budget = min(int(header.get("max_instructions", 1_000_000)), MAX_INSTRUCTIONS)
    info, pe_image = load(f, header.get("arch", "auto"))
    arch = info["arch"]
    imports = info["imports"]
    stubs = {}
    if imports:
        fmt = imports["fmt"]
        for i, (slot, name) in enumerate(imports["rvas"].items()):
            addr = STUB_BASE + i * 16
            stubs[addr] = name
            struct.pack_into(fmt, pe_image, slot, addr)
        info["segments"] = [(info["load_base"], bytes(pe_image))]
    in_off, in_len = header.get("input_offset", 0), header.get("input_length", 0)
    if in_len > INPUT_MAX:
        raise Refuse("input buffer is larger than 16 MiB")
    if in_off + in_len > len(f):
        raise Refuse("input range lies outside the file")
    in_data = f[in_off:in_off + in_len]
    args = [{"input": INPUT_BASE, "input_len": len(in_data)}.get(a, a) for a in header.get("args", [])]
    if "input" in header.get("args", []) and not in_data:
        raise Refuse("call_args names input, but no input range was given")
    if not all(isinstance(a, int) for a in args) or len(args) > 8:
        raise Refuse("call_args must be numbers, input or input_len; at most 8")
    work = [(INPUT_BASE, INPUT_BASE + INPUT_MAX), (STUB_BASE, STUB_BASE + MAX_IMPORTS * 16), (SENTINEL, SENTINEL + PAGE),
            (STACK_BASE, STACK_BASE + STACK_SIZE)]
    pages = _merge((va & -PAGE, (va + len(d) + PAGE - 1) & -PAGE) for va, d in info["segments"])
    if any(lo < w_hi and w_lo < hi for lo, hi in pages for w_lo, w_hi in work):
        raise Refuse("the image overlaps the emulator work regions")
    if sum(hi - lo for lo, hi in pages) > MAX_MAPPED:
        raise Refuse("mapped image is outside the emulation limit")
    if not any(lo <= start < hi for lo, hi in pages):
        return {"error": f"start 0x{start:x} is outside the mapped file; mapped: "
                         + ", ".join(f"0x{lo:x}-0x{hi:x}" for lo, hi in pages[:8]), "load_base": info["load_base"]}

    uc = unicorn.Uc(*ARCHES[arch])
    for lo, hi in pages:
        uc.mem_map(lo, hi - lo, unicorn.UC_PROT_ALL)
    for va, d in info["segments"]:
        uc.mem_write(va, d)
    uc.mem_map(INPUT_BASE, INPUT_MAX, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
    uc.mem_map(STUB_BASE, MAX_IMPORTS * 16, unicorn.UC_PROT_ALL)
    uc.mem_map(SENTINEL, PAGE, unicorn.UC_PROT_ALL)
    uc.mem_map(STACK_BASE, STACK_SIZE, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
    if in_data:
        uc.mem_write(INPUT_BASE, in_data)
    _set_call(uc, info, arch, args, SENTINEL)

    state = {"fault": None, "api": None, "cut": False, "written": set()}

    def on_write(_uc, _access, addr, size, _value, _user):
        blocks = state["written"]
        if len(blocks) < MAX_WRITTEN_BLOCKS:
            blocks.update(range(addr >> 4, ((addr + max(size, 1) - 1) >> 4) + 1))
        else:
            state["cut"] = True

    def on_invalid(_uc, access, addr, size, _value, _user):
        state["fault"] = {"address": addr, "size": size, "access": access}
        return False

    def on_stub(emu, addr, _size, _user):
        state["api"] = stubs.get(addr, "?")
        emu.emu_stop()

    uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, on_write)
    uc.hook_add(unicorn.UC_HOOK_MEM_UNMAPPED | unicorn.UC_HOOK_MEM_PROT, on_invalid)
    uc.hook_add(unicorn.UC_HOOK_CODE, on_stub, begin=STUB_BASE, end=STUB_BASE + MAX_IMPORTS * 16 - 1)

    until = SENTINEL if end is None else end
    t0 = time.monotonic()
    error = None
    try:
        uc.emu_start(start, until, timeout=TIMEOUT_S * 1_000_000, count=budget)
    except unicorn.UcError as exc:
        error = str(exc)
    elapsed = time.monotonic() - t0
    regs = {name: uc.reg_read(reg) for name, reg in REGS[arch].items()}
    pc = uc.reg_read(PC[arch])
    # ARM reports the Thumb bit in neither pc nor until consistently, so both compare without it.
    if error:
        reason = "fault"
    elif state["api"]:
        reason = "api_call"
    elif (pc & ~1) == (until & ~1):
        reason = "returned" if end is None else "end_reached"
    elif elapsed >= TIMEOUT_S - 1:
        reason = "timeout"
    else:
        reason = "budget"

    regions, total, cut = [], 0, state["cut"]
    for lo, hi in _merge(((b << 4, (b + 1) << 4) for b in state["written"])):
        if len(regions) >= MAX_REGIONS or total >= MAX_REGION_BYTES:
            cut = True
            break
        size = min(hi - lo, MAX_REGION_BYTES - total)
        cut = cut or size < hi - lo
        try:
            data = bytes(uc.mem_read(lo, size))
        except unicorn.UcError:
            continue
        total += size
        regions.append({"kind": _kind(lo, info), "address": lo, "size": size, "sha256": hashlib.sha256(data).hexdigest(),
                        "data_b64": base64.b64encode(data).decode("ascii")})
    return {"engine": f"unicorn-{unicorn.__version__}", "format": info["format"], "arch": arch, "load_base": info["load_base"],
            "start": start, "end": end, "stop_reason": reason, "pc": pc, "api": state["api"], "fault": state["fault"],
            "error": None, "engine_error": error, "budget": budget, "elapsed_s": round(elapsed, 3),
            "return_value": regs[RET[arch]], "registers": regs, "regions": regions, "regions_truncated": cut,
            "input": {"offset": in_off, "length": len(in_data), "address": INPUT_BASE if in_data else None,
                      "sha256": hashlib.sha256(in_data).hexdigest() if in_data else None},
            "file_sha256": hashlib.sha256(f).hexdigest()}


def main():
    if sys.argv[1:] != ["emulate"]:
        print("unknown operation", file=sys.stderr)
        return 64
    raw = sys.stdin.buffer.read(MAX_INPUT)
    size = struct.unpack_from("<I", raw, 0)[0] if len(raw) >= 4 else 0
    if not 0 < size <= 65536 or len(raw) < 4 + size:
        print("bad frame", file=sys.stderr)
        return 65
    header = json.loads(raw[4:4 + size])
    try:
        out = emulate(header, raw[4 + size:])
    except Refuse as exc:
        out = {"error": str(exc)}
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
