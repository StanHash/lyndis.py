# Any copyright is dedicated to the Public Domain.
# https://creativecommons.org/publicdomain/zero/1.0/

"""
This is lyndis. One day, hopefully, this will be a well-written native
application rather than a shoddy python script.

It takes a set of object files, compiled using conventional toolchains (GCC...),
and inserts it into a binary (in our case, a GBA ROM).

These objects may or may not contain special "directives" embedded into section
names, which gets lyndis behave in special ways. These directives must be
prefixed by "__lyn.".

For example, a section whose name ends with "__lyn.replace_GetUnit" will replace
the function GetUnit.

List of supported directives:

* "at_<address>": specifies that this section should be placed at the given
  address.

* "replace_<name>": specifies that this section replaces the symbol named <name>
  that section may declare a symbol with the same name at the start of the
  section.
  If <name> is a function, lyndis is allowed to insert trampolines if the new
  section doesn't fit the function (if that function has a size parameter).

* meta: a __lyn.meta contains strings that are commands to lyndis. This is where
  you can purge reference symbols ("purge <name>") or define free space
  ("free <address> <length>"). Command strings are separated by the null
  character.
"""

import sys
import re

from os.path import commonpath

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection

from typing import BinaryIO


class RefSymbol:
    name: str
    addr: int
    size: int
    is_func: bool
    is_replaced: bool

    def __init__(self, name: str, addr: int, size: int, is_func: bool):
        self.name = name
        self.addr = addr
        self.size = size
        self.is_func = is_func
        self.is_replaced = False


class LynSymbol:
    name: str
    section: int
    offset: int

    def __init__(self, name: str, sec_idx: int, offset: int) -> None:
        self.name = name
        self.section = sec_idx
        self.offset = offset

    def __repr__(self):
        return f'LynSymbol("{self.name}", {self.section}, {self.offset})'


class LynRelocation:
    offset: int
    symbol: int
    addend: int | None
    rel_type: int

    def __init__(
        self, offset: int, sym_idx: int, addend: int | None, rel_type: int
    ) -> None:
        self.offset = offset
        self.symbol = sym_idx
        self.addend = addend
        self.rel_type = rel_type


class LynSection:
    name: str
    base_data: bytearray
    relocations: list[LynRelocation]
    addr: int | None
    align: int
    do_not_place: bool
    writable: bool

    def __init__(self, name: str, base_data: bytes, align: int = 4) -> None:
        self.name = name
        self.base_data = bytearray(base_data)
        self.relocations = []  # to be populated
        self.addr = None
        self.align = align
        self.do_not_place = False
        self.writable = False

    def __repr__(self):
        return f'LynSection("{self.name}", b"{self.base_data}", {self.relocations}, {self.addr if self.addr is not None else -1:08X})'


LYN_SEC_ABS = -1

# big global tables

# reference_symbols is sorted by addr
reference_symbols: list[RefSymbol] = []
reference_dict: dict[str, int] = {}

symbol_table: list[LynSymbol | None] = []
global_symbol_dict: dict[str, int] = {}

section_table: list[LynSection] = []
free_regions: list[tuple[int, int]] = []  # (addr, size)


def add_undefined_symbol(name: str) -> int:
    global global_symbol_dict
    global symbol_table

    # if symbol already in table, return existing idx
    if name in global_symbol_dict:
        return global_symbol_dict[name]

    # add undefined symbol (None)
    idx = len(symbol_table)
    global_symbol_dict[name] = idx
    symbol_table.append(None)
    return idx


def add_global_symbol(lyn_symbol: LynSymbol) -> int:
    global global_symbol_dict
    global symbol_table

    name = lyn_symbol.name

    if name in global_symbol_dict:
        idx = global_symbol_dict[name]

        if symbol_table[idx] is None:
            symbol_table[idx] = lyn_symbol
            return idx

        else:
            # TODO: handle weak symbols!
            print(f"Error: redefinition of global symbol (name = {lyn_symbol.name})")
            return -1

    else:
        idx = len(symbol_table)
        global_symbol_dict[name] = idx
        symbol_table.append(lyn_symbol)
        return idx


def add_local_symbol(lyn_symbol: LynSymbol) -> int:
    # just add symbol
    idx = len(symbol_table)
    symbol_table.append(lyn_symbol)
    return idx


def get_global_symbol(name: str) -> LynSymbol | None:
    if name in global_symbol_dict:
        idx = global_symbol_dict[name]
        return symbol_table[idx]

    return None


SHF_WRITE = 0x01
SHF_ALLOC = 0x02
SHN_UNDEF = 0
SHN_ABS = 0xFFF1
SHN_COMMON = 0xFFF2


def add_elf(elf_io: BinaryIO, elf_name: str | None):
    elf = ELFFile(elf_io)

    # each PROGBITS and NOBITS section becomes a lyndis Section

    # STEP 1. We note what sections we are interested in
    # And allocate new entries in the big table.

    # This map can be implemented as an array when porting to C
    elf_to_lyn_section: dict[int, int] = {}

    for i in range(elf.num_sections()):
        section = elf.get_section(i)

        if (section["sh_flags"] & SHF_ALLOC) != 0:
            global section_table
            # TODO: if NOBITS, this is all zeroes

            sec_name = (
                f"{section.name}({elf_name})" if elf_name is not None else section.name
            )

            lyn_sec = LynSection(sec_name, section.data(), section["sh_addralign"])

            if (section["sh_flags"] & SHF_WRITE) != 0:
                lyn_sec.writable = True

            elf_to_lyn_section[i] = len(section_table)
            section_table.append(lyn_sec)

    # print(elf_to_lyn_section)

    # STEP 2. We initialize our symbols.

    elf_to_lyn_symbols: dict[int, dict[int, int]] = {}

    for shn in range(elf.num_sections()):
        section = elf.get_section(shn)

        if isinstance(section, SymbolTableSection):
            this_map = {}

            for i in range(section.num_symbols()):
                elf_sym = section.get_symbol(i)

                sym_name = elf_sym.name
                sym_value = elf_sym.entry.st_value
                elf_sec_idx = elf_sym.entry.st_shndx

                # print(f'"{sym_name}" {sym_value}')

                if elf_sec_idx in elf_to_lyn_section:
                    lyn_sec = elf_to_lyn_section[elf_sec_idx]

                    # handle signed offset
                    if sym_value >= 0x80000000:
                        sym_value -= 0x100000000

                    lyn_sym = LynSymbol(sym_name, lyn_sec, sym_value)

                elif elf_sec_idx == "SHN_UNDEF":
                    # TODO: assert bind is STB_GLOBAL
                    this_map[i] = add_undefined_symbol(sym_name)
                    continue
                elif elf_sec_idx == "SHN_COMMON":
                    # TODO: this isn't allowed
                    print("ERROR: SHN_COMMON")
                    exit(1)
                elif elf_sec_idx == "SHN_ABS":
                    lyn_sym = LynSymbol(sym_name, LYN_SEC_ABS, sym_value)

                else:
                    # Ignore this symbol as it doesn't pertain to a section we care for
                    # TODO: we could remember this to raise errors
                    continue

                # print(elf_sym.entry.st_info.bind)

                match elf_sym.entry.st_info.bind:
                    case "STB_GLOBAL":
                        # NOTE: can error (if another instance of this symbol already defined)
                        this_map[i] = add_global_symbol(lyn_sym)

                    case "STB_LOCAL":
                        this_map[i] = add_local_symbol(lyn_sym)

                    case "STB_WEAK":
                        print("ERROR: we don't support weak symbols yet!")
                        # TODO: weak symbols are not supported yet
                        exit(1)

                    case _:
                        # TODO: this is an error
                        pass

            elf_to_lyn_symbols[shn] = this_map

    # STEP 3. Relocations

    for shn in range(elf.num_sections()):
        section = elf.get_section(shn)

        if isinstance(section, RelocationSection):
            sym_idx = section["sh_link"]
            sec_idx = section["sh_info"]

            if sec_idx not in elf_to_lyn_section:
                continue

            is_rela = section.is_RELA()

            # print(sec_idx)
            # print(elf.get_section(sec_idx).name)

            sym_ind = elf_to_lyn_symbols[sym_idx]
            lyn_sec = section_table[elf_to_lyn_section[sec_idx]]

            for i in range(section.num_relocations()):
                elf_rel = section.get_relocation(i)
                elf_sym_idx = elf_rel.entry.r_info_sym
                addend = elf_rel.entry.r_addend if is_rela else None
                rel_type = elf_rel.entry.r_info_type
                offset = elf_rel.entry.r_offset
                lyn_rel = LynRelocation(offset, sym_ind[elf_sym_idx], addend, rel_type)
                lyn_sec.relocations.append(lyn_rel)

    # print(elf_to_lyn_symbols)


RE_LYN_DIRECTIVE = re.compile(r".*__lyn\.(?P<directive>[a-zA-Z0-9_]+)")
RE_LYN_AT = re.compile(r"at_(?P<expr>\w+)")
RE_LYN_REPLACE = re.compile(r"replace_(?P<name>\w+)")
RE_LYN_META = re.compile(r"meta")


def handle_directive_at(m, idx, sec):
    expr = m.group("expr")

    expr = int(expr, base=0)
    sec.addr = expr


generated_sections = []


# NOTE: most of these are unused for now

# bx pc ; nop ; ldr ip, lit ; bx ip ; lit: .word 0
LYN_JUMP_BASE = b"\x78\x47\xc0\x46\x00\xc0\x9f\xe5\x1c\xff\x2f\xe1\x00\x00\x00\x00"

# bx pc ; nop
LYN_JUMP_BXPC_THM = b"\x78\x47\xc0\x46"

# push {r4, r5} ; ldr r4, lit ; str r4, [sp, #4] ; pop {r4, pc} ; lit: .word 0
LYN_JUMP_BASE_THM2THM = b"\x30\xb4\x01\x4c\x01\x94\x10\xbd\x00\x00\x00\x00"

# ldr ip, lit ; bx ip ; lit: .word 0
LYN_JUMP_BASE_ARM2ANY = b"\x00\xc0\x9f\xe5\x1c\xff\x2f\xe1\x00\x00\x00\x00"

# ldr pc, lit ; lit: .word 0
LYN_JUMP_BASE_ARM2ARM = b"\x04\xf0\x1f\xe5\x00\x00\x00\x00"

LYN_JUMP_BASE_THM2ANY = LYN_JUMP_BXPC_THM + LYN_JUMP_BASE_ARM2ANY
LYN_JUMP_BASE_THM2ARM = LYN_JUMP_BXPC_THM + LYN_JUMP_BASE_ARM2ARM

LYN_JUMP_MAP = {
    ("thm", "thm"): LYN_JUMP_BASE_THM2ANY,
    ("thm", "arm"): LYN_JUMP_BASE_THM2ARM,
    ("arm", "thm"): LYN_JUMP_BASE_ARM2ANY,
    ("arm", "arm"): LYN_JUMP_BASE_ARM2ARM,
}


def handle_directive_replace(m, idx, sec):
    name = m.group("name")

    # STEP 1. find name in reference

    if name not in reference_dict:
        print(
            f"Failed to handle section directive {sec.name}: couldn't find {name} in reference"
        )
        exit(1)

    sym_idx = reference_dict[name]
    sym = reference_symbols[sym_idx]

    # STEP 2. check if sec fits in name
    # if it doesn't:
    #   if name is function, insert veneer
    #   if name is object, error

    purge_size = sym.size  # purge_size is the size we can mark as free

    if purge_size == 0:
        if sym_idx < len(reference_symbols) - 1:
            next_sym = reference_symbols[sym_idx + 1]
            max_size = next_sym.addr - sym.addr
        else:
            # case where we are replacing the very last reference symbol
            # leave enough room for a trampoline
            max_size = 0xC

    else:
        max_size = purge_size

    replace_addr = sym.addr

    if sym.is_func:
        # remove thumb bit
        replace_addr = replace_addr & ~1

    # find any fixed ("at") section that's already within the range here
    # and reduce the max_size accordingly
    for other_sec in section_table:
        if other_sec.addr is not None:
            other_addr = other_sec.addr

            if other_addr >= replace_addr and other_addr < replace_addr + max_size:
                max_size = other_addr - replace_addr

    if len(sec.base_data) <= max_size:
        # the section fits inline, which is nice
        sec.addr = replace_addr
        sym.is_replaced = True

        remains = purge_size - len(sec.base_data)

        if remains > 0:
            free_regions.append((replace_addr + purge_size - remains, remains))

    else:
        if sym.is_func and max_size >= 0x0C:
            # case of function: insert trampoline

            # find head symbol of section
            target_sym_idx = -1

            for i, sec_sym in enumerate(symbol_table):
                # make sure that the thumb bit of both symbols is the same
                # IDEALLY, we would just find a STT_FUNC symbol but I didn't care to remember that yet
                # (it would allow for mixed thumb/ARM replaces)

                if sec_sym is not None:
                    if sec_sym.section == idx and sec_sym.offset == (sym.addr & 1):
                        target_sym_idx = i
                        break

            if target_sym_idx >= 0:
                global generated_sections

                trampoline_name = f"__lyn_generated.jump_to_new_{name}"

                # TODO: check thumb bit of func we replace
                # priorities should be: arm2arm, arm2any, thm2arm, thm2any, thm2thm
                if max_size >= 0x10:
                    # generic efficient thm->any trampoline (16 bytes)
                    trampoline_sec = LynSection(trampoline_name, LYN_JUMP_BASE_THM2ANY)
                    # R_ARM_ABS32 2 @ +0x0C
                    trampoline_rel = LynRelocation(0x0C, target_sym_idx, None, 2)

                elif (symbol_table[target_sym_idx].offset & 1) == 1:
                    # packed slow thm->thm trampoline (12 bytes)
                    trampoline_sec = LynSection(trampoline_name, LYN_JUMP_BASE_THM2THM)
                    # R_ARM_ABS32 2 @ +0x08
                    trampoline_rel = LynRelocation(0x08, target_sym_idx, None, 2)

                trampoline_sec.relocations.append(trampoline_rel)

                trampoline_sec.addr = replace_addr
                sym.is_replaced = True

                generated_sections.append(trampoline_sec)

                remains = purge_size - len(trampoline_sec.base_data)

                if remains > 0:
                    free_regions.append((replace_addr + purge_size - remains, remains))

        else:
            print(
                f"Failed to handle section directive {sec.name}: couldn't fit section at {name}"
            )
            exit(1)


def handle_directive_meta(m, idx, sec: LynSection):
    sec.do_not_place = True

    for item in sec.base_data.split(b"\x00"):
        item = item.decode("utf-8").strip()

        if len(item) == 0:
            continue

        tokens = item.split()

        match tokens[0]:
            case "purge":
                # purge <name>...
                for name in tokens[1:]:
                    if name in reference_dict:
                        idx = reference_dict[name]
                        ref_sym = reference_symbols[idx]

                        # TODO: is_purged
                        ref_sym.is_replaced = True

                        if ref_sym.size > 0:
                            free_regions.append((ref_sym.addr, ref_sym.size))

            case "free":
                # free <addr> <size>
                addr = int(tokens[1], base=0)
                size = int(tokens[2], base=0)

                free_regions.append((addr, size))


DIRECTIVES = [
    (RE_LYN_META, handle_directive_meta),
    (RE_LYN_AT, handle_directive_at),
    (RE_LYN_REPLACE, handle_directive_replace),
]


def set_fixed_section_addrs():
    # we may be adding trampolines during this, but we don't care about them
    len_without_trampolines = len(section_table)

    # handle in directives order rather than section order
    # we need all "at" directives to be handled before "replace"
    # to reduce possibilities of overlaps from inplace replaces
    # (ideally those at sections would be "weak" and replace takes prio but lazy)

    handled = {}

    for directive_regexp, directive_handler in DIRECTIVES:
        for i in range(len_without_trampolines):
            if i in handled and handled[i][1]:
                continue

            sec = section_table[i]

            m = RE_LYN_DIRECTIVE.match(sec.name)

            if m is not None:
                directive = m.group("directive")

                if i not in handled:
                    handled[i] = (directive, False)

                m = directive_regexp.match(directive)

                if m is not None:
                    directive_handler(m, i, sec)
                    handled[i] = (directive, True)

            else:
                pass
                # print(f"No match: {sec.name}")

    all_success = True

    for i in handled:
        (directive, success) = handled[i]

        if not success:
            print(f"Unknown lyn directive: {directive}")
            all_success = False

    if not all_success:
        exit(1)

    # HACK: generated_sections shouldn't be a thing. We should just have sections be
    section_table.extend(generated_sections)


def split_free_region_at_range(addr: int, size: int):
    global free_regions

    beg_addr: int = addr
    end_addr: int = addr + size

    # not very efficient (on brand for lyndis.py)
    for j in range(len(free_regions)):
        (free_addr, free_size) = free_regions[j]
        free_end: int = free_addr + free_size

        # four possible cases:

        # - the section overlaps the entirety of the free region
        if beg_addr <= free_addr and end_addr >= free_end:
            free_regions[j] = (beg_addr, 0)

        # - the section overlaps the start of the free region
        elif beg_addr <= free_addr and end_addr > free_addr:
            free_regions[j] = (end_addr, free_end - end_addr)

        # - the section overlaps the end of the free region
        elif beg_addr < free_end and end_addr >= free_end:
            free_regions[j] = (free_addr, beg_addr - free_addr)

        # - the section overlaps the middle of the free region
        elif beg_addr < free_end and end_addr > free_addr:
            free_regions[j] = (free_addr, beg_addr - free_addr)
            free_regions.append((end_addr, free_end - end_addr))


def split_free_regions_at_fixed_sections():
    """
    Make it so free sections don't overlap with sections at fixed addrs
    NOTE: free regions are NOT sorted after this!!!
    """

    global free_regions

    for i, sec in enumerate(section_table):
        if sec.addr is None:
            continue

        split_free_region_at_range(sec.addr, len(sec.base_data))


def set_not_fixed_section_addrs():
    global free_regions

    bin_beg = binary_region[0]
    bin_end = binary_region[0] + binary_region[1]

    free_regions.sort()

    for i, sec in enumerate(section_table):
        if sec.do_not_place:
            continue

        this_size = len(sec.base_data)

        # HACK: align this_size to 4 bytes because I don't want to worry about alignment issues
        this_size = (this_size + 3) // 4 * 4

        # check if this should go into the binary, basically
        is_meaningful_data = any(b != 0 for b in sec.base_data)
        is_writable = sec.writable

        if is_meaningful_data and is_writable:
            print(f"Writable non-zero sections are not supported (name = {sec.name})")

        if sec.addr is None and this_size > 0:
            for j, (addr, size) in enumerate(free_regions):
                # make sure we would start at a appropriately aligned addr
                if (addr % sec.align) != 0:
                    offset_for_align = sec.align - addr % sec.align
                    addr += offset_for_align
                    size -= offset_for_align

                if size < this_size:
                    continue

                in_binary = (addr + size > bin_beg) and (addr < bin_end)

                if is_writable == in_binary:
                    continue

                free_regions[j] = (addr + this_size, size - this_size)
                sec.addr = addr
                break

            if sec.addr is None:
                print(
                    f"Couldn't find a suitable region of this section (name = {sec.name}, size = {this_size})"
                )
                print(f"{bin_beg:08X} {bin_end:08X}")

                for addr, size in free_regions:
                    print(f"{addr:08X} {size:08X}")

                exit(1)


def lookup_sym_name(idx: int):
    sym = symbol_table[idx]

    if sym is not None:
        return sym.name

    else:
        # wtf this is hella slow???
        reverse_name_dict = {
            global_symbol_dict[name]: name for name in global_symbol_dict
        }

        return reverse_name_dict[idx]


def lookup_sym_value(idx: int):
    sym = symbol_table[idx]

    if sym is not None:
        if sym.section >= 0:
            sec = section_table[sym.section]
            if sec.addr is not None:
                return sec.addr + sym.offset
            else:
                print(f"Couldn't evaluate symbol {sym.name}: section wasn't mapped!")
                exit(1)

        else:
            # absolute symbol
            return sym.offset

    else:
        # wtf this is hella slow???
        reverse_name_dict = {
            global_symbol_dict[name]: name for name in global_symbol_dict
        }

        if idx in reverse_name_dict:
            name = reverse_name_dict[idx]

            if name in reference_dict:
                ref_idx = reference_dict[name]
                ref_sym = reference_symbols[ref_idx]

                if not ref_sym.is_replaced:
                    return ref_sym.addr

                else:
                    # this symbol was "replaced" but there was no replacement
                    # this means that the symbol was purged
                    print(f"Evaluation of purged referenced symbol! (name = {name})")
                    exit(1)

            else:
                print(f"Evaluation of undefined symbol! (name = {name})")
                exit(1)


# UNUSED, we ended up using an alternative strategy for accounting for those
def add_reference_symbols():
    for sym in reference_symbols:
        if sym.is_replaced:
            continue

        lyn_sym = LynSymbol(sym.name, LYN_SEC_ABS, sym.addr)
        add_global_symbol(lyn_sym)


# R_ARM_NONE 0
# R_ARM_ABS32 2
# R_ARM_REL32 3
# R_ARM_ABS16 5
# R_ARM_ABS8 8
# R_ARM_THM_CALL 10
# R_ARM_CALL 28
# R_ARM_JUMP24 29
# R_ARM_V4BX 40
# R_ARM_THM_JUMP11 102
# R_ARM_THM_JUMP8 103


def compute_relocations():
    for sec in section_table:
        for rel in sec.relocations:
            off = rel.offset

            match rel.rel_type:
                case 2:  # R_ARM_ABS32
                    val = lookup_sym_value(rel.symbol)
                    addend = (
                        int.from_bytes(sec.base_data[off : off + 4], "little")
                        if rel.addend is None
                        else rel.addend
                    )
                    sec.base_data[off : off + 4] = (val + addend).to_bytes(4, "little")

                case 3:  # R_ARM_REL32
                    val = lookup_sym_value(rel.symbol) - (sec.addr + off)
                    addend = (
                        int.from_bytes(sec.base_data[off : off + 4], "little")
                        if rel.addend is None
                        else rel.addend
                    )
                    sec.base_data[off : off + 4] = (val + addend).to_bytes(4, "little")

                case 10:  # R_ARM_THM_CALL
                    hi = int.from_bytes(sec.base_data[off : off + 2], "little")
                    lo = int.from_bytes(sec.base_data[off + 2 : off + 4], "little")

                    value = lookup_sym_value(rel.symbol) - (sec.addr + off)

                    if rel.addend is None:
                        addend = ((hi & 0x07FF) << 12) + ((lo & 0x07FF) << 1)

                        # account for sign bit
                        if addend >= 0x400000 != 0:
                            addend -= 0x800000

                    else:
                        addend = rel.addend

                    complete_value = value + addend

                    if (complete_value < -0x400000) or (complete_value >= 0x400000):
                        target_name = lookup_sym_name(rel.symbol)
                        print(
                            f"ERROR: {sec.addr + off:08X}: {sec.name}+{off}: {'target' if target_name is None else target_name} out of BL range (disp: {complete_value:X})"
                        )
                        exit(1)

                    hi = (hi & 0xF800) | ((complete_value >> 12) & 0x07FF)
                    lo = (lo & 0xF800) | ((complete_value >> 1) & 0x07FF)

                    sec.base_data[off : off + 2] = hi.to_bytes(2, "little")
                    sec.base_data[off + 2 : off + 4] = lo.to_bytes(2, "little")

                case 28:  # R_ARM_CALL
                    base = int.from_bytes(sec.base_data[off : off + 4], "little")
                    value = lookup_sym_value(rel.symbol) - (sec.addr + off)

                    if rel.addend is None:
                        addend = (base & 0x00FFFFFF) * 4

                        # account for sign bit
                        if addend >= 0x2000000 != 0:
                            addend -= 0x4000000

                    else:
                        addend = rel.addend

                    complete_value = value + addend

                    if (complete_value < -0x2000000) or (complete_value >= 0x2000000):
                        target_name = lookup_sym_name(rel.symbol)
                        print(
                            f"ERROR: {sec.addr + off:08X}: {sec.name}+{off}: {'target' if target_name is None else target_name} out of BL range (disp: {complete_value:X})"
                        )
                        exit(1)

                    complete_ins = (base & 0xFF000000) | (
                        (complete_value // 4) & 0x00FFFFFF
                    )

                    sec.base_data[off : off + 4] = complete_ins.to_bytes(4, "little")

                case 40:  # R_ARM_V4BX
                    # do nothing!
                    pass

                case _:
                    # TODO: error
                    print(
                        f"Unhandled relocation type: {rel.rel_type} at {sec.name}+{off}"
                    )
                    exit(1)


def apply_sections(data: bytearray, data_addr: int):
    binary_beg_addr = data_addr
    binary_end_addr = data_addr + len(data)

    for sec in section_table:
        if sec.addr is not None:
            beg = sec.addr
            end = sec.addr + len(sec.base_data)

            if beg >= binary_beg_addr and end <= binary_end_addr:
                beg_off = beg - data_addr
                end_off = end - data_addr

                data[beg_off:end_off] = sec.base_data

            else:
                # TODO: make sure the data isn't meaningful (all zeroes)
                pass


binary_region = (0x08000000, 0x02000000)


def load_reference(path: str):
    global reference_symbols
    global reference_dict
    global free_regions
    global binary_region

    try:
        with open(path, "r") as f:
            lines = [line for line in f.readlines()]

    except IOError:
        sys.exit(f"Couldn't open reference `{path}` for read")

    found_binary_region = False

    for line in lines:
        line = line.strip()

        if len(line) == 0 or line[0] == "#":
            continue

        tokens = line.split()

        match tokens[0]:
            case "fun":
                # fun <addr> <name> [size]
                addr = int(tokens[1], base=0)
                name = tokens[2]
                size = int(tokens[3], base=0) if len(tokens) > 3 else 0

                reference_symbols.append(RefSymbol(name, addr, size, True))

            case "dat":
                # dat <addr> <name> [size]
                addr = int(tokens[1], base=0)
                name = tokens[2]
                size = int(tokens[3], base=0) if len(tokens) > 3 else 0

                reference_symbols.append(RefSymbol(name, addr, size, False))

            case "free":
                # free <addr> <size>
                addr = int(tokens[1], base=0)
                size = int(tokens[2], base=0)

                free_regions.append((addr, size))

            case "binary":
                # bin <addr> <size>
                addr = int(tokens[1], base=0)
                size = int(tokens[2], base=0)

                if found_binary_region:
                    print("WARNING: duplicate binary region in reference, using last")

                found_binary_region = True
                binary_region = (addr, size)

    if not found_binary_region:
        print("WARNING: no binary region in reference, using GBA ROM as default")

    reference_symbols.sort(key=lambda ref_sym: ref_sym.addr)

    for i, ref_sym in enumerate(reference_symbols):
        reference_dict[ref_sym.name] = i


def check_for_overlaps():
    if len(section_table) == 0:
        return

    order = [i for i in range(len(section_table)) if section_table[i].addr is not None]
    order.sort(key=lambda i: section_table[i].addr)

    last_tail = section_table[order[0]].addr + len(section_table[order[0]].base_data)

    for i in range(1, len(order)):
        sec_0 = section_table[order[i - 1]]
        sec_1 = section_table[order[i]]

        head = sec_1.addr

        if head < last_tail:
            print(f"COLLISION BETWEEN {sec_0.name} AND {sec_1.name}")
            print(f"{sec_0.name}: {sec_0.addr:08X}[{len(sec_0.base_data)}] ")
            print(f"{sec_1.name}: {sec_1.addr:08X}[{len(sec_1.base_data)}] ")
            exit(1)

        last_tail = head + len(sec_1.base_data)


def check_for_redefined_symbols():
    for name in reference_dict:
        # ignore replaced (purged) symbols
        if reference_symbols[reference_dict[name]].is_replaced:
            continue

        if name in global_symbol_dict:
            sym_idx = global_symbol_dict[name]
            lyn_sym = symbol_table[sym_idx]

            if lyn_sym is not None:
                print(f"ERROR: redefinition of reference symbol (name = {name})")


def produce_map_file(file_path: str):
    # sections ordered by address
    sec_idxes = sorted(
        [i for i in range(len(section_table)) if section_table[i].addr is not None],
        key=lambda i: section_table[i].addr,
    )

    # symbols ordered by address
    # messy
    sym_idxes = sorted(
        [
            i
            for i in range(len(symbol_table))
            if symbol_table[i] is not None
            and symbol_table[i].section is not None
            and section_table[symbol_table[i].section].addr is not None
        ],
        key=lambda i: (
            section_table[symbol_table[i].section].addr + symbol_table[i].offset
            if symbol_table[i].section != LYN_SEC_ABS
            else symbol_table[i].offset
        ),
    )

    with open(file_path, "w") as f:
        f.write("\nSYMBOLS\n")

        for idx in sym_idxes:
            sym = symbol_table[idx]

            if len(sym.name) == 0 or "$" in sym.name:
                continue

            if sym.section == LYN_SEC_ABS:
                f.write(f"  {sym.offset:08X} {sym.name} (ABS)\n")

            else:
                sec = section_table[sym.section]
                addr = sec.addr + sym.offset

                if sym.offset >= 0:
                    loc_fmt = f"{sec.name}+{sym.offset}"
                else:
                    loc_fmt = f"{sec.name}-{-sym.offset}"

                f.write(f"  {addr:08X} {sym.name} ({loc_fmt})\n")

        # do sections second because I find it less useful than symbols
        f.write("SECTIONS\n")

        for idx in sec_idxes:
            sec = section_table[idx]
            f.write(f"  {sec.addr:08X} {len(sec.base_data):08X} {sec.name}\n")

        f.write("\nFREE REGIONS REMAINING\n")

        for addr, size in sorted(free_regions):
            if size == 0:
                continue

            f.write(f"  {addr:08X} {size:08X}\n")


def main(args: list[str]):
    import argparse

    parser = argparse.ArgumentParser(
        prog="lyndis",
        description="Inject a set of 32bit ARM object files into an existing raw binary.",
    )

    # positionals
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("objects", nargs="*")

    # flags
    parser.add_argument("-r", "--reference")
    parser.add_argument("-m", "--map")

    arguments = parser.parse_args(args[1:])

    objects = arguments.objects
    reference_path = arguments.reference
    output_binary = arguments.output
    input_binary = arguments.input
    output_map = arguments.map

    if reference_path is not None:
        load_reference(reference_path)

    common_path_len = 0

    # try to print shorter paths
    if len(objects) > 1:
        try:
            common_path_len = len(commonpath(objects))

            if common_path_len > 0:
                common_path_len += 1  # HACK: omit leading '/'

        except ValueError:
            pass

    # LOAD ELVES
    for object_path in objects:
        with open(object_path, "rb") as f:
            add_elf(f, object_path[common_path_len:])

    set_fixed_section_addrs()

    # split free regions at fixed sections locations
    split_free_regions_at_fixed_sections()

    # NOTE about free_regions: ideally we prioritize the regions freed by replaces

    # add just the canonical free space for 16MiB GBA ROMs
    # free_regions.append((0x09000000, 0x01000000))

    global free_regions
    free_regions.sort()

    set_not_fixed_section_addrs()

    # check for overlaps!
    check_for_overlaps()

    # check for redefinition of reference symbols
    check_for_redefined_symbols()

    # we shouldn't actually do this...
    # instead, lookup the reference in compute_relocations
    # add_reference_symbols()

    compute_relocations()

    # print(symbol_table)
    # print(section_table)

    binary_beg_addr = binary_region[0]
    binary_end_addr = binary_region[0] + binary_region[1]

    neeeded_binary_size = 0

    # Compute needed binary size
    for sec in section_table:
        if sec.addr is not None:
            beg = sec.addr
            end = sec.addr + len(sec.base_data)
            if beg >= binary_beg_addr and end <= binary_end_addr:
                neeeded_binary_size = max(neeeded_binary_size, end - binary_beg_addr)

    # Get bytes from binary
    try:
        with open(input_binary, "rb") as f:
            data = bytearray(f.read())

        if len(data) < neeeded_binary_size:
            data.extend(0 for _ in range(neeeded_binary_size - len(data)))

    except IOError:
        data = bytearray(0 for _ in range(neeeded_binary_size))

    # Apply sections to data
    apply_sections(data, binary_beg_addr)

    # Write to binary
    with open(output_binary, "wb") as f:
        f.write(data)

    # Write map file
    if output_map is not None:
        produce_map_file(output_map)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
