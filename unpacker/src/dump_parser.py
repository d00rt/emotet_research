from configuration import *
import StringIO
import struct
import base64
import yara
import os

"""
    class EmotetDumpFileParser:
        Simple class for parsing the memory dump where
        Emotet drops unpacked files.

        Also this class can reconstruct the emotet payload.

    class SimplePEFileParser:
        Simple and custom class for reading PE files.
"""

__author__ = "d00rt - @D00RT_RM"

__version__ = "1.0.0"
__maintainer__ = "d00rt - @D00RT_RM"
__email__ = "d00rt.fake@gmail.com"
__status__ = "Testing"


# ====
BYTE    = 0x01
WORD    = 0x02
DWORD   = 0x04

_SIZE_TABLE = {
    BYTE:   "B",
    WORD:   "=H",
    DWORD:  "=L",
}

# ==== DOS MZ Header
PE_HEADER_OFFSET        = 0x3C

# ==== PE Header
SIGNATURE               = 0x00
NUMBER_OF_SECTIONS      = 0x06
CODE_BASE               = 0x2C
IMAGE_BASE              = 0x34
FILE_ALIGNMENT          = 0x3C
SECTIONS_HEADER         = 0xF8

# ==== Section Header
SECTION_HEADER_SIZE     = 0x28
NAME                    = 0x00
VIRTUAL_SIZE            = 0x08
VIRTUAL_ADDRESS         = 0x0C
SIZE_OF_RAW_DATA        = 0x10
POINTER_TO_RAW_DATA     = 0x14
CHARACTERISTICS         = 0x24


class SimplePEFileParser():

    def __init__(self, data=None, filename=None):
        self.DATA = ''
        self.ALIGNED = False

        if data == None and filename == None:
            raise Exception("No sources provided.")

        if data:
            self.DATA = data

        if filename:
            with open(filename, "rb") as f:
                self.DATA = f.read()

        if self.DATA == '':
            raise Exception("Provided data soruces for creating the reader are empty")

        if not self.simple_check_valid_pe_file():
            raise Exception("Provided data isn't a valid PE file.")

    def patch_bytes(self, off, data):
        size = len(data)
        b_data = bytearray(self.DATA)
        b_data[off: off + size] = data
        self.DATA = str(b_data)

    def _fix_file_alignment_field(self, alignment=0x200):
        b_data = bytearray(self.DATA)
        pe_header = self.read_data_as_integer(PE_HEADER_OFFSET, DWORD)

        b_data[pe_header + alignment: pe_header + alignment + 4] = \
        struct.pack("=L", alignment)
        self.DATA = str(b_data)

    def _fix_section_header_content_and_alignment_field(self, alignment):
        b_data = bytearray(self.DATA)
        pe_header = self.read_data_as_integer(PE_HEADER_OFFSET, DWORD)
        num_of_sections = self.read_data_as_integer(pe_header + NUMBER_OF_SECTIONS, WORD)
        section_header = pe_header + SECTIONS_HEADER 

        aligned_section_header_content = self._get_aligned_section_header_content(alignment)
        self._fix_file_alignment_field(alignment)

        for i in range(num_of_sections):
            b_data[section_header + (i * SECTION_HEADER_SIZE) + POINTER_TO_RAW_DATA: \
            section_header + (i * SECTION_HEADER_SIZE) + POINTER_TO_RAW_DATA + 4] = \
            struct.pack("=L", aligned_section_header_content[i][0])
            
            b_data[section_header + (i * SECTION_HEADER_SIZE) + SIZE_OF_RAW_DATA: \
            section_header + (i * SECTION_HEADER_SIZE) + SIZE_OF_RAW_DATA + 4] = \
            struct.pack("=L", aligned_section_header_content[i][1])
        self.DATA = str(b_data)

    def _fill_data(self, raw_size):
        return '\x00' * raw_size

    def _align(self, value, aligment):
        r = value % aligment
        if r > 0:
            value += aligment - r

        return value

    def _get_aligned_section_header_content(self, aligment=0x200):
        aligned_section_headers = []
        for s in self._get_section_header_content():
            raw_addr, raw_size, virtual_address, virtual_size, name, characteristics = s
            raw_addr_aligned = self._align(raw_addr, aligment)
            raw_size_aligned =  self._align(raw_size, aligment)
            if aligned_section_headers:
                r_a, r_s = aligned_section_headers[-1]
                raw_addr_aligned = r_a + r_s
            aligned_section_headers.append((raw_addr_aligned, raw_size_aligned))

        return aligned_section_headers

    def _get_data_from_offset(self, offset, size):
        return self.DATA[offset: offset + size]

    def read_data_as_integer(self, offset, size):
        if not size in _SIZE_TABLE.keys():
            return None

        return struct.unpack(_SIZE_TABLE[size], self._get_data_from_offset(offset, size))[0]

    def read_data_as_buffer(self, offset, size):
        if size < 0:
            return None
        return self._get_data_from_offset(offset, size)

    def _get_pe_header(self):
        return self.read_data_as_integer(PE_HEADER_OFFSET, DWORD)

    def _get_pe_signature(self):
        pe_header = self._get_pe_header()
        if not pe_header:
            return False
        return self.read_data_as_integer(pe_header + SIGNATURE, DWORD)

    def _get_pe_image_base(self):
        pe_header = self._get_pe_header()
        if not pe_header:
            return False
        return self.read_data_as_integer(pe_header + IMAGE_BASE, DWORD)

    def _get_pe_code_base(self):
        pe_header = self._get_pe_header()
        if not pe_header:
            return False
        return self.read_data_as_integer(pe_header + IMAGE_BASE, DWORD)

    def _get_number_of_sections(self):
        pe_header = self._get_pe_header()
        return self.read_data_as_integer(pe_header + NUMBER_OF_SECTIONS, WORD)

    def _get_content_of_sections(self):
        sections_content = []
        for r_a, r_s, v_a, v_s, n, c in self._get_section_header_content():
            section_data = self.DATA[r_a: r_a + r_s]
            sections_content.append(section_data)

        return sections_content

    def _get_file_alignment(self):
        pe_header = self._get_pe_header()
        return self.read_data_as_integer(pe_header + FILE_ALIGNMENT, DWORD)

    def _get_number_of_sections(self):
        pe_header = self._get_pe_header()
        return self.read_data_as_integer(pe_header + NUMBER_OF_SECTIONS, WORD)
        
    def _get_section_header(self):
        pe_header = self._get_pe_header()
        return pe_header + SECTIONS_HEADER

    def _check_pe_signature(self):
        pe_signature = self._get_pe_signature()
        if not pe_signature:
            return False

        return 0x00004550 == pe_signature

    def _get_section_header_content(self):
        sections_header_array = []
        section_header = self._get_section_header()
        for i in range(self._get_number_of_sections()):
            name = self.read_data_as_buffer(section_header + (i * SECTION_HEADER_SIZE) + NAME, DWORD * 2).replace('\x00', '')
            pointer_to_raw_data = self.read_data_as_integer(section_header + (i * SECTION_HEADER_SIZE) + POINTER_TO_RAW_DATA, DWORD)
            size_of_raw_data = self.read_data_as_integer(section_header + (i * SECTION_HEADER_SIZE) + SIZE_OF_RAW_DATA, DWORD)
            virtual_address = self.read_data_as_integer(section_header + (i * SECTION_HEADER_SIZE) + VIRTUAL_ADDRESS, DWORD)
            virtual_size = self.read_data_as_integer(section_header + (i * SECTION_HEADER_SIZE) + VIRTUAL_SIZE, DWORD)
            characteristics = self.read_data_as_integer(section_header + (i * SECTION_HEADER_SIZE) + CHARACTERISTICS, DWORD)
            sections_header_array.append((pointer_to_raw_data, size_of_raw_data, virtual_address, virtual_size, name, characteristics))
        return sections_header_array

    def _search_for_mz(self):
        while len(self.DATA):
            mz_index = self.DATA.index("MZ")
            self.DATA = self.DATA[mz_index:]

            if self._check_pe_signature():
                return True
        return False

    def simple_check_valid_pe_file(self):
        if not self._search_for_mz():
            return False

        return True

    def _get_data_based_on_section_header(self):
        last_section = self._get_section_header_content()[-1]
        r_a, r_s, e, m, o, t = last_section
        return self.DATA[:r_a + r_s]

    def align_file(self):
        sec_content = self._get_content_of_sections()

        header = self.DATA[: self._get_section_header_content()[0][0]]
        aligned_section_header_content = self._get_aligned_section_header_content()

        data = header
        data += self._fill_data(aligned_section_header_content[0][0] - len(data))

        i = 1
        # Copy all sections except the last one
        for s in sec_content[:-1]:
            data += s
            data += self._fill_data(aligned_section_header_content[i][0] - len(data))
            i += 1

        data += sec_content[i - 1]
        data += self._fill_data(aligned_section_header_content[i - 1][0] + aligned_section_header_content[i - 1][1] - len(data))
        
        self.DATA = data
        self._fix_section_header_content_and_alignment_field(0x200)
        self.ALIGNED = True

    def from_va_to_offset(self, va):
        offset = 0
        va -= self._get_pe_image_base()
        for r_a, r_s, v_a, v_s, n, c in self._get_section_header_content():
            if va < v_a + v_s:
                offset = va - v_a
                break
        return r_a + offset

    def write(self, filename):
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))

        with open(filename, "wb") as f:
            f.write(self._get_data_based_on_section_header())

class EmotetDumpFileParser():
        
    def __init__(self, data=None, dumpfilename=None):
        self.DUMP_DATA = ''
        self.PE_LAYER_2 = None
        self.PE_BROKEN_PAYLOAD = None
        self.PE_PAYLOAD = None
        self.RSA_CONFIG = []
        self.IPS_CONFIG = []

        if data == None and dumpfilename == None:
            raise Exception("No sources provided.")

        if data:
            self.DUMP_DATA = data

        if dumpfilename:
            with open(dumpfilename, "rb") as f:
                self.DUMP_DATA = f.read()

        if self.DUMP_DATA == '':
            raise Exception("Provided data soruces for creating the reader are empty")

    def _get_end_of_layer_2_in_the_dump(self):
        mz_index = self.DUMP_DATA.index("MZ")
        end_of_file = self.PE_LAYER_2._get_section_header_content()[-1][0] + self.PE_LAYER_2._get_section_header_content()[-1][1]
        return mz_index + end_of_file

    def parse(self):
        self.PE_LAYER_2 = SimplePEFileParser(data=self.DUMP_DATA)
        layer_2_end_offset = self._get_end_of_layer_2_in_the_dump()
        self.PE_BROKEN_PAYLOAD = SimplePEFileParser(data=self.DUMP_DATA[layer_2_end_offset:])
        self.PE_PAYLOAD = SimplePEFileParser(data=self.DUMP_DATA[layer_2_end_offset:])

        self.PE_LAYER_2.align_file()

    def write(self, fname_layer_2, fname_payload):
        if fname_layer_2:
            self.PE_LAYER_2.write(fname_layer_2)

        if fname_payload:
            self.PE_BROKEN_PAYLOAD.write(fname_payload)

    def _get_rsa_from_offset(self, offset):
        return self.PE_PAYLOAD.read_data_as_buffer(offset, 0x6A)

    def _get_ip_from_raw_ip(self, raw_ip):
        return '.'.join([str(struct.unpack("B", c)[0]) for c in raw_ip][::-1])

    def _get_port_from_raw_port(self, raw_port):
        return str((struct.unpack("=L", raw_port)[0]) & 0xFFFF)

    def _get_ips_from_offset(self, offset):
        i = 0
        ip = self.PE_PAYLOAD.read_data_as_buffer(offset + (i * 8), 0x4)
        port = self.PE_PAYLOAD.read_data_as_buffer(offset + (i * 8) + 4, 0x4)

        while ip != "\x00\x00\x00\x00" and port != "\x00\x00\x00\x00":
            yield self._get_ip_from_raw_ip(ip) + ":" + self._get_port_from_raw_port(port)
            i += 1

            ip = self.PE_PAYLOAD.read_data_as_buffer(offset + (i * 8), 0x4)
            port = self.PE_PAYLOAD.read_data_as_buffer(offset + (i * 8) + 4, 0x4)


    def get_static_config(self, match_rsa, match_code):
        if match_code:
     
            for m in match_code:
                for string in m.strings:
                    if string[1] == '$ip_pattern':
                        ips_rva = struct.unpack("=L", string[2][9: 9 + 4])[0]
                        ips_off = self.PE_PAYLOAD.from_va_to_offset(ips_rva)
                        for ip_port in self._get_ips_from_offset(ips_off):
                            self.IPS_CONFIG.append(ip_port)

                    elif string[1] == '$key':
                        rsa_rva = struct.unpack("=L", string[2][17: 17 + 4])[0]
                        rsa_off = self.PE_PAYLOAD.from_va_to_offset(rsa_rva)
                        self.RSA_CONFIG.append(self._get_rsa_from_offset(rsa_off))

                    elif string[1] == '$old_version_pattern':
                        ips_rva = struct.unpack("=L", string[2][16: 16 + 4])[0]
                        ips_off = self.PE_PAYLOAD.from_va_to_offset(ips_rva)
                        for ip_port in self._get_ips_from_offset(ips_off):
                            self.IPS_CONFIG.append(ip_port)

                        rsa_rva = struct.unpack("=L", string[2][36: 36 + 4])[0]
                        rsa_off = self.PE_PAYLOAD.from_va_to_offset(rsa_rva)
                        rsa_rva = self.PE_PAYLOAD.read_data_as_integer(rsa_off, DWORD)
                        rsa_off = self.PE_PAYLOAD.from_va_to_offset(rsa_rva)
                        self.RSA_CONFIG.append(self._get_rsa_from_offset(rsa_off))

        if not match_code and match_rsa:
            for m in match_rsa:
                for string in m.strings:
                    self.RSA_CONFIG.append(string[2])

        self.RSA_CONFIG = set(self.RSA_CONFIG)
        self.IPS_CONFIG = set(self.IPS_CONFIG)
        self.RSA_CONFIG = list(self.RSA_CONFIG)
        self.IPS_CONFIG = list(self.IPS_CONFIG)

    def print_hex(self, data, chunk_size=16):
        output = []
        i = 0
        while i < len(data):
            chunk = " ".join("{0:02X}".format(ord(c)) for c in data[i * chunk_size: i * chunk_size + chunk_size])
            if len(chunk):
                output.append(chunk)
            i += 1

        return output

    def _unhook_get_array_data(self, off, size):
        hook_array = []
        raw_hooks = self.PE_LAYER_2.read_data_as_buffer(off, size * 0x0C)
        for i in range(size):
            src_data_va = struct.unpack("=L", raw_hooks[i * 0x0C:  (i * 0x0C) + 0x04])[0]
            dst_off_in_payload = struct.unpack("=L", raw_hooks[i * 0xC + 4: (i * 0xC + 4) + 4])[0]
            _size = struct.unpack("=L", raw_hooks[i * 0xC + 8: (i * 0xC + 8) + 4])[0]
            hook_array.append((src_data_va, dst_off_in_payload, _size))
        return hook_array

    def _unhook(self, match):
        for m in match:
            for string in m.strings:
                if string[1] == '$hooks1':
                    hook_rva = struct.unpack("=L", string[2][10: 10 + 4])[0]
                    hook_off = self.PE_LAYER_2.from_va_to_offset(hook_rva)

                if string[1] == '$hooks2':
                    hook_rva = struct.unpack("=L", string[2][7: 7 + 4])[0]
                    hook_off = self.PE_LAYER_2.from_va_to_offset(hook_rva)

                elif string[1] == '$size':
                    array_size = struct.unpack("=L", string[2][10: 10 + 4])[0]

        if array_size and hook_off:
            hook_array = self._unhook_get_array_data(hook_off, array_size)

            # Get .text section data for resizeing the destination offset
            # dst_offset are rva of .text section
            for r_a, r_s, v_a, v_s, n, c in self.PE_PAYLOAD._get_section_header_content():
                if n == ".text":
                    break

            for src_va, dst_off, size in hook_array:
                src_off = self.PE_LAYER_2.from_va_to_offset(src_va)
                hook_data = self.PE_LAYER_2.read_data_as_buffer(src_off, size)
                dst_off = dst_off - v_a + r_a
                self.PE_PAYLOAD.patch_bytes(dst_off, hook_data)
            return True
        else:
            return False

    def unhook(self):
        rules_hooks = yara.compile(FILE_YARA_HOOKS)

        match = rules_hooks.match(data=self.PE_LAYER_2.DATA)

        if match:
            return self._unhook(match)
            
        return []

    def write_static_config(self, rsa_filename, ips_filename):
        if rsa_filename:
            if not os.path.exists(os.path.dirname(rsa_filename)):
                os.makedirs(os.path.dirname(rsa_filename))

            with open(rsa_filename, "wb") as f:
                for rsa_key in self.RSA_CONFIG:
                    f.write("== RSA KEY BASE64 ==\r\n")
                    f.write(base64.b64encode(rsa_key))
                    f.write("\r\n")
                    f.write("== RSA KEY BASE64 END ==\r\n")
                    f.write("\r\n")
                    f.write("== RSA KEY YARA EXPORT ==\r\n")
                    for l in self.print_hex(rsa_key):
                        f.write("{0}\r\n".format(l))
                    f.write("== RSA KEY YARA EXPORT END ==\r\n")

        if ips_filename:
            if not os.path.exists(os.path.dirname(ips_filename)):
                os.makedirs(os.path.dirname(ips_filename))

            with open(ips_filename, "wb") as f:
                for ip in self.IPS_CONFIG:
                    f.write("{0}\r\n".format(ip))
