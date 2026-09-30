import sys
import lief
import struct

if len(sys.argv) != 4:
    print("Usage: python merge_imports.py <pe_original> <pe_to_be_fixed> <pe_out>")
    sys.exit(1)

arg1 = sys.argv[1]
arg2 = sys.argv[2]
arg3 = sys.argv[3]

pe_org = pe = lief.PE.parse(arg1)
pe_fix = pe = lief.PE.parse(arg2)

def get_imports(pe):
    
    slots = []

    for lib in pe.imports:
        slots.append(lib)

    return slots

imports_merged = get_imports(pe_fix) + get_imports(pe_org)

last_section = pe_fix.sections[-1]

def build_idata(imports_rva, imports):

    # Image Directory Table
    idt_size = (len(imports) + 1) * 20
    idt_data = bytearray()

    # Image Lookup Table
    ilt_size = sum([len(lib.entries) + 1 for lib in imports]) * 4
    ilt_rva = idt_size
    ilt_data = bytearray()

    strings_lookup = {} # (str, has_hint_prefix)
    strings_rva = ilt_rva + ilt_size
    strings_data = bytearray()

    for lib in imports:

        dll = lib.name.lower()
        
        if (dll, False) not in strings_lookup:
            strings_lookup[(dll, False)] = strings_rva + len(strings_data)
            strings_data += dll.encode() + b"\x00"

        num_entries = len(lib.entries)

        idt_data += struct.pack("<IIIII",
            imports_rva + ilt_rva + len(ilt_data),      # OriginalFirstThunk
            0,                                          # TimeDateStamp
            0,                                          # ForwarderChain
            imports_rva + strings_lookup[(dll, False)], # Name
            lib.import_address_table_rva                # FirstThunk
        )

        for entry in lib.entries:
            if entry.is_ordinal:
                ilt_data += struct.pack("<I", entry.ilt_value)
            else:
                if (entry.name, True) not in strings_lookup:
                    strings_lookup[(entry.name, True)] = strings_rva + len(strings_data)
                    strings_data += struct.pack("<H", entry.hint)
                    strings_data += entry.name.encode() + b"\x00"
                
                ilt_data += struct.pack("<I", imports_rva + strings_lookup[(entry.name, True)])

        ilt_data += struct.pack("<I", 0)

    idt_data += struct.pack("<IIIII", 0, 0, 0, 0, 0)

    return idt_data + ilt_data + strings_data

idata = build_idata(last_section.virtual_address, imports_merged)

def align(size, alignment):
    return (size + alignment - 1) // alignment * alignment

# Since Scylla appends the idata section, we can simply replace it
file_alignment = pe_fix.optional_header.file_alignment
section_alignment = pe_fix.optional_header.section_alignment

raw_size = align(len(idata), file_alignment)
virtual_size = align(len(idata), section_alignment)
sizeof_image = align(last_section.virtual_address + virtual_size, section_alignment)

with open(arg2, "rb") as f:
    pe_fix_raw = f.read()

# Remove section...
pe_fix_raw = pe_fix_raw[:last_section.pointerto_raw_data]

# ...and add new
pe_fix_raw += idata.ljust(raw_size, b"\x00")

opt_header_offset = pe_fix.dos_header.addressof_new_exeheader + 4 + 20
section_table_offset = opt_header_offset + pe_fix.header.sizeof_optional_header
section_header_offset = section_table_offset + (len(pe_fix.sections) - 1) * 40

# Fix VirtualSize
pe_fix_raw = pe_fix_raw[:section_header_offset + 8] + struct.pack("<I", virtual_size) + pe_fix_raw[section_header_offset + 8 + 4:]

# Fix RawSize
pe_fix_raw = pe_fix_raw[:section_header_offset + 0x10] + struct.pack("<I", raw_size) + pe_fix_raw[section_header_offset + 0x10 + 4:]

# Fix SizeOfImage
pe_fix_raw = pe_fix_raw[:opt_header_offset + 0x38] + struct.pack("<I", sizeof_image) + pe_fix_raw[opt_header_offset + 0x38 + 4:]

# Fix address of ImportDirectory and size
pe_fix_raw = pe_fix_raw[:opt_header_offset + 0x68] + struct.pack("<II", last_section.virtual_address, (len(imports_merged) + 1) * 20) + pe_fix_raw[opt_header_offset + 0x68 + 4 + 4:]

with open(arg3, "wb") as f:
    f.write(pe_fix_raw)