"""
vm/opcodes.py
=============
Custom instruction set for Pyrph VM.

Every build calls OpcodeMap.generate() with a random seed,
producing a unique byte→opcode mapping. Two files obfuscated
from the same source will have completely different bytecode.

Architecture: stack-based with 8 registers (hybrid).

Encoding:
    [1 byte: opcode_byte] [N bytes: args]

Arg byte counts per instruction type:
    0  — no args
    1  — 1-byte pool index or register 0–7
    2  — 2-byte jump target (big-endian absolute byte offset)
    3  — two 1-byte args (a, b)
"""
from __future__ import annotations
import random
from dataclasses import dataclass, field
from typing import Dict, Optional, List


# ── Instruction table ─────────────────────────────────────────────────────
# (name, arg_bytes, description)

INSTRUCTION_DEFS: Dict[str, tuple] = {
    # stack
    "LOAD_CONST":    (1, "push consts[a]"),
    "LOAD_NAME":     (1, "push frame[names[a]]"),
    "STORE_NAME":    (1, "frame[names[a]] = pop()"),
    "DEL_NAME":      (1, "del frame[names[a]]"),
    "POP":           (0, "discard top"),
    "DUP":           (0, "duplicate top"),
    "ROT2":          (0, "swap top 2"),
    "ROT3":          (0, "rotate top 3  a,b,c→c,a,b"),
    # registers
    "REG_LOAD":      (1, "push regs[a]"),
    "REG_STORE":     (1, "regs[a] = pop()"),
    "REG_LOADK":     (3, "regs[a] = consts[b]"),
    "REG_MOV":       (3, "regs[a] = regs[b]"),
    # arithmetic
    "ADD":           (0, "b+a"),
    "SUB":           (0, "b-a"),
    "MUL":           (0, "b*a"),
    "DIV":           (0, "b/a"),
    "FLOORDIV":      (0, "b//a"),
    "MOD":           (0, "b%a"),
    "POW":           (0, "b**a"),
    "NEG":           (0, "-top"),
    "POS":           (0, "+top"),
    # bitwise
    "BAND":          (0, "b&a"),
    "BOR":           (0, "b|a"),
    "BXOR":          (0, "b^a"),
    "BINV":          (0, "~top"),
    "BSHL":          (0, "b<<a"),
    "BSHR":          (0, "b>>a"),
    # compare
    "CMP_EQ":        (0, "b==a"),
    "CMP_NE":        (0, "b!=a"),
    "CMP_LT":        (0, "b<a"),
    "CMP_LE":        (0, "b<=a"),
    "CMP_GT":        (0, "b>a"),
    "CMP_GE":        (0, "b>=a"),
    "CMP_IN":        (0, "b in a"),
    "CMP_NOT_IN":    (0, "b not in a"),
    "CMP_IS":        (0, "b is a"),
    "CMP_IS_NOT":    (0, "b is not a"),
    "NOT":           (0, "not top"),
    # jumps  (2-byte big-endian absolute byte offset into bytecode)
    "JMP":           (2, "unconditional"),
    "JMP_TRUE":      (2, "pop; jump if truthy"),
    "JMP_FALSE":     (2, "pop; jump if falsy"),
    "JMP_TRUE_PEEK": (2, "peek; jump if truthy  (and short-circuit)"),
    "JMP_FALSE_PEEK":(2, "peek; jump if falsy   (or short-circuit)"),
    # functions
    "MAKE_FUNC":     (1, "VMFunc from consts[a]"),
    "CALL":          (1, "call fn with a pos-args"),
    "CALL_KW":       (3, "call fn with a pos + b kw args"),
    "CALL_METHOD":   (3, "obj.names[a](*stack[-b:])"),
    "RETURN":        (0, "return top"),
    # attributes / items
    "GET_ATTR":      (1, "push top.names[a]"),
    "SET_ATTR":      (1, "obj.names[a] = val"),
    "DEL_ATTR":      (1, "del top.names[a]"),
    "GET_ITEM":      (0, "obj[key]"),
    "SET_ITEM":      (0, "obj[key]=val"),
    "DEL_ITEM":      (0, "del obj[key]"),
    "SLICE":         (0, "obj[lo:hi]"),
    # builders
    "BUILD_LIST":    (1, "list from top a items"),
    "BUILD_TUPLE":   (1, "tuple from top a items"),
    "BUILD_DICT":    (1, "dict from top a*2 items"),
    "BUILD_SET":     (1, "set from top a items"),
    "BUILD_STR":     (1, "join top a strings"),
    # iteration
    "GET_ITER":      (0, "iter(top)"),
    "FOR_ITER":      (2, "next(iter) or jump to target"),
    "UNPACK":        (1, "unpack top into a items"),
    # import
    "IMPORT":        (1, "__import__(names[a])"),
    "IMPORT_FROM":   (3, "__import__(names[a]).names[b]"),
    # exceptions
    "SETUP_TRY":     (2, "push try frame; except at target"),
    "POP_TRY":       (0, "pop try frame"),
    "RAISE":         (0, "raise top"),
    # misc
    "FORMAT_VAL":    (0, "str(top)"),
    "HALT":          (0, "stop VM"),
}

ALL_OPCODES: List[str] = list(INSTRUCTION_DEFS.keys())
NUM_OPCODES: int       = len(ALL_OPCODES)

assert NUM_OPCODES <= 256, "Too many opcodes"


@dataclass
class OpcodeMap:
    """
    Bidirectional mapping: opcode_name ↔ byte_value.
    Freshly shuffled on every obfuscation run.
    """
    name_to_byte: Dict[str, int]
    byte_to_name: Dict[int, str]

    def __getitem__(self, name: str) -> int:
        return self.name_to_byte[name]

    def get_name(self, byte: int) -> Optional[str]:
        return self.byte_to_name.get(byte)

    def to_translation_table(self) -> bytes:
        """
        256-byte array: raw_byte → logical opcode index (0-based in ALL_OPCODES).
        Used by C VM to dispatch without knowing opcode names.
        Index 255 = unknown/junk opcode.
        """
        name_to_idx = {n: i for i, n in enumerate(ALL_OPCODES)}
        arr = [255] * 256
        for byte_val, name in self.byte_to_name.items():
            arr[byte_val] = name_to_idx.get(name, 255)
        return bytes(arr)

    @classmethod
    def generate(cls, seed: Optional[int] = None) -> "OpcodeMap":
        """Create a new randomised opcode map. Call with seed=None for fresh per-build map."""
        rng    = random.Random(seed)
        pool   = list(range(256))
        rng.shuffle(pool)
        values = pool[:NUM_OPCODES]
        n2b    = {name: values[i] for i, name in enumerate(ALL_OPCODES)}
        b2n    = {v: n for n, v in n2b.items()}
        return cls(name_to_byte=n2b, byte_to_name=b2n)


@dataclass
class Bytecode:
    """Compiled VM bytecode for one module or function."""
    instructions: bytes          # raw encoded instruction stream
    constants:    list           # const pool (Python values + nested Bytecode)
    names:        list           # name pool (str)
    arg_names:    list           # parameter names (empty for module-level)
    opcode_map:   OpcodeMap      # the map used to compile this bytecode
