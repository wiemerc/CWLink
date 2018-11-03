#!/usr/bin/env python3



import sys
import logging
from logging import log, DEBUG, INFO, WARN, ERROR, CRITICAL
from struct import pack, unpack
from ctypes import BigEndianStructure, c_ubyte, c_ushort, c_uint, addressof, sizeof, memmove


def hexdump(buffer):
    dump = ''
    pos  = 0
    while (pos < len(buffer)):
        dump += '%04x  ' % pos
        line = ''
        for i in range(pos, pos + 16):
            if i >= len(buffer):
                break
            
            dump += '%02x ' % buffer[i]
            if buffer[i] >= 0x20 and buffer[i] <= 0x7e:
                line += chr(buffer[i])
            else:
                line += '.'
                
        if len(line) < 16:
            dump += ' ' * 3 * (16 - len(line))
            
        dump += '\t' + line + '\n'
        pos += 16
        
    return dump
        
        
class Stab(BigEndianStructure):
    _fields_ = [
        ('st_offset', c_uint),
        ('st_type', c_ubyte),
        ('st_other', c_ubyte),
        ('st_desc', c_ushort),
        ('st_value', c_uint),
    ]


class HunkReader(object):
    # file types
    FILE_EXE = 1
    FILE_OBJ = 2
    
    # block types from from dos/doshunks.h
    HUNK_UNIT	  = 999
    HUNK_NAME	  = 1000
    HUNK_CODE	  = 1001
    HUNK_DATA	  = 1002
    HUNK_BSS	  = 1003
    HUNK_RELOC32  = 1004
    HUNK_RELOC16  = 1005
    HUNK_RELOC8	  = 1006
    HUNK_EXT	  = 1007
    HUNK_SYMBOL	  = 1008
    HUNK_DEBUG	  = 1009
    HUNK_END	  = 1010
    HUNK_HEADER	  = 1011
    HUNK_OVERLAY  = 1013
    HUNK_BREAK	  = 1014
    HUNK_DREL32	  = 1015
    HUNK_DREL16	  = 1016
    HUNK_DREL8	  = 1017
    HUNK_LIB	  = 1018
    HUNK_INDEX	  = 1019
    
    # symbol types from from dos/doshunks.h
    EXT_SYMB   = 0
    EXT_DEF	   = 1
    EXT_ABS	   = 2
    EXT_RES	   = 3
    EXT_REF32  = 129
    EXT_COMMON = 130
    EXT_REF16  = 131
    EXT_REF8   = 132
    EXT_DEXT32 = 133
    EXT_DEXT16 = 134
    EXT_DEXT8  = 135
        
    # stab names taken from binutils-gdb/include/aout/stab.def
    N_EXT = 0x01
    _stab_type_to_name = {
        0x00: 'N_UNDF',
        0x01: 'N_EXT',
        0x02: 'N_ABS',
        0x04: 'N_TEXT',
        0x06: 'N_DATA',
        0x08: 'N_BSS',
        0x0a: 'N_INDR',
        0x0c: 'N_FN_SEQ',
        0x0d: 'N_WEAKU',
        0x0e: 'N_WEAKA',
        0x0f: 'N_WEAKT',
        0x10: 'N_WEAKD',
        0x11: 'N_WEAKB',
        0x12: 'N_COMM',
        0x14: 'N_SETA',
        0x16: 'N_SETT',
        0x18: 'N_SETD',
        0x1a: 'N_SETB',
        0x1c: 'N_SETV',
        0x1e: 'N_WARNING',
        0x1f: 'N_FN',
        0x20: 'N_GSYM',
        0x22: 'N_FNAME',
        0x24: 'N_FUN',
        0x26: 'N_STSYM',
        0x28: 'N_LCSYM',
        0x2a: 'N_MAIN',
        0x2c: 'N_ROSYM',
        0x2e: 'N_BNSYM',
        0x30: 'N_PC',
        0x32: 'N_NSYMS',
        0x34: 'N_NOMAP',
        0x38: 'N_OBJ',
        0x3c: 'N_OPT',
        0x40: 'N_RSYM',
        0x42: 'N_M2C',
        0x44: 'N_SLINE',
        0x46: 'N_DSLINE',
        0x48: 'N_BSLINE',
        0x4a: 'N_DEFD',
        0x4C: 'N_FLINE',
        0x4E: 'N_ENSYM',
        0x50: 'N_EHDECL',
        0x54: 'N_CATCH',
        0x60: 'N_SSYM',
        0x62: 'N_ENDM',
        0x64: 'N_SO',
        0x66: 'N_OSO',
        0x6c: 'N_ALIAS',
        0x80: 'N_LSYM',
        0x82: 'N_BINCL',
        0x84: 'N_SOL',
        0xa0: 'N_PSYM',
        0xa2: 'N_EINCL',
        0xa4: 'N_ENTRY',
        0xc0: 'N_LBRAC',
        0xc2: 'N_EXCL',
        0xc4: 'N_SCOPE',
        0xd0: 'N_PATCH',
        0xe0: 'N_RBRAC',
        0xe2: 'N_BCOMM',
        0xe4: 'N_ECOMM',
        0xe8: 'N_ECOML',
        0xea: 'N_WITH',
        0xF0: 'N_NBTEXT',
        0xF2: 'N_NBDATA',
        0xF4: 'N_NBBSS',
        0xF6: 'N_NBSTS',
        0xF8: 'N_NBLCS',
        0xfe: 'N_LENG',
    }


    def __init__(self, fname):
        self.fname = fname


    def read(self):
        with open(self.fname, 'rb') as self._fobj:
            hnum = 0
            while True:
                try:
                    btype = self._read_word()
                    log(INFO, "hunk #%d, block type = 0x%04x (%d)", hnum, btype, btype)
                    if btype == HunkReader.HUNK_END:
                        # possibly another hunk follows, nothing else to do
                        log(INFO, "hunk #%d finished", hnum)
                        hnum += 1
                        continue
                    else:
                        HunkReader._read_funcs[btype](self)
                        
                except EOFError:
                    if btype == HunkReader.HUNK_END:
                        break
                    else:
                        log(ERROR, "encountered EOF while reading file '%s'", self.fname)
                        break
                        
                except KeyError as ex:
                    log(ERROR, "block type %s not known or implemented", ex)
                    break

                except Exception as ex:
                    log(ERROR, "error occured while reading file: %s", ex)
                    break


    def _read_byte(self):
        buffer = self._fobj.read(1)
        if buffer:
            return unpack('>B', buffer)[0]
        else:
            raise EOFError
    
    
    def _read_short(self):
        buffer = self._fobj.read(2)
        if buffer:
            return unpack('>H', buffer)[0]
        else:
            raise EOFError
    
    
    def _read_word(self):
        buffer = self._fobj.read(4)
        if buffer:
            return unpack('>L', buffer)[0]
        else:
            raise EOFError
    
    
    def _read_string(self, nchars):
        buffer = self._fobj.read(nchars)
        if buffer:
            return unpack('%ds' % nchars, buffer)[0].decode('ascii').replace('\x00', '')
        else:
            return EOFError

    
    @staticmethod
    def _get_string_from_buffer(buffer):
        idx = 0
        while idx < len(buffer) and buffer[idx] != 0:
            idx += 1
        if idx < len(buffer):
            return buffer[0:idx].decode()
        else:
            raise ValueError("no terminating NULL byte found in buffer")


    def _read_header_block(self):
        log(INFO, "reading HUNK_HEADER block... file is a AmigaDOS executable")
        log(DEBUG, "long words reserved for resident libraries: %d", self._read_word())
        log(DEBUG, "number of hunks: %d", self._read_word())
        fhunk = self._read_word()
        lhunk = self._read_word()
        log(DEBUG, "number of first hunk: %d", fhunk)
        log(DEBUG, "number of last hunk: %d", lhunk)
        for hnum in range(fhunk, lhunk + 1):
            log(DEBUG, "size (in bytes) of hunk #%d: %d", hnum, self._read_word() * 4)
    
    
    def _read_unit_block(self):
        log(INFO, "reading HUNK_UNIT block... file is a AmigaDOS object file")
        log(INFO, "unit name: %s", self._read_string(self._read_word() * 4))
        
        
    def _read_name_block(self):
        log(INFO, "reading HUNK_NAME block...")
        log(INFO, "hunk name: %s", self._read_string(self._read_word() * 4))
        
        
    def _read_code_block(self):
        log(INFO, "reading HUNK_CODE block...")
        nwords = self._read_word()
        log(DEBUG, "size (in bytes) of code block: %d", nwords * 4)
        # TODO: create hexdump with the symbols, references and addresses to be relocated highlighted
        log(DEBUG, "hex dump of code block:\n" + hexdump(self._fobj.read(nwords * 4)))
        
        
    def _read_data_block(self):
        log(INFO, "reading HUNK_DATA block...")
        nwords = self._read_word()
        log(DEBUG, "size (in bytes) of data block: %d", nwords * 4)
        # TODO: create hexdump with the symbols, references and addresses to be relocated highlighted
        log(DEBUG, "hex dump of data block:\n" + hexdump(self._fobj.read(nwords * 4)))
        
        
    def _read_bss_block(self):
        log(INFO, "reading HUNK_BSS block...")
        nwords = self._read_word()
        log(DEBUG, "size (in bytes) of BSS block: %d", nwords * 4)
        
        
    def _read_ext_block(self):
        log(INFO, "reading HUNK_EXT block...")
        while True:
            type_len = self._read_word()
            if type_len == 0:
                break
            
            stype = (type_len & 0xff000000) >> 24
            sname = self._read_string((type_len & 0x00ffffff) * 4)
            
            if stype in (HunkReader.EXT_DEF, HunkReader.EXT_ABS, HunkReader.EXT_RES):
                # definition
                log(DEBUG, "definition of symbol (type = %d): %s = 0x%08x", stype, sname, self._read_word())
            elif stype in (HunkReader.EXT_REF8, HunkReader.EXT_REF16, HunkReader.EXT_REF32):
                # reference(s)
                nrefs = self._read_word()
                for i in range(0, nrefs):
                    log(DEBUG, "reference to symbol %s (type = %d): 0x%08x", sname, stype, self._read_word())
            else:
                raise ValueError(f"symbol type {stype} not supported")
        
        
    def _read_symbol_block(self):
        log(INFO, "reading HUNK_SYMBOL block...")
        while True:
            nwords = self._read_word()
            if nwords == 0:
                break
            
            sname = self._read_string(nwords * 4)
            sval  = self._read_word()
            log(DEBUG, "%s = 0x%08x", sname, sval)
        
        
    def _read_reloc32_block(self):
        log(INFO, "reading HUNK_RELOC32 block...")
        while True:
            noffsets = self._read_word()
            if noffsets == 0:
                break
            
            refhnum = self._read_word()
            log(DEBUG, "relocations referencing hunk #%d:", refhnum)
            for i in range(0, noffsets):
                log(DEBUG, "position = 0x%08x", self._read_word())
            
        
    def _read_debug_block(self):
        log(INFO, "reading HUNK_DEBUG block...")
        nwords = self._read_word()
        data   = self._fobj.read(nwords * 4)
        offset = 0

        # The content of a HUNK_DEBUG block was not specified by Commodore. Different compilers
        # used different formats for the debug information. We support two different formats:
        # - the LINE format used by SAS/C that only contains a line / offset table. This format
        #   is also generated by VBCC / VLINK and the code below is based on the function
        #   linedebug_hunks() in the file t_amigahunk.c from VLINK.
        # - the STABS format that was also popular on UNIX and was used by GCC that contains
        #   type definitions, a list of all functions and variables and a line / offset table
        log(DEBUG, "hexdump of HUNK_DEBUG block:\n" + hexdump(data))

        if data[offset + 4:offset + 8] == b'LINE':
            log(DEBUG, "format is assumed to be LINE (SAS/C or VBCC)")
            log(DEBUG, "section offset: 0x%08x", unpack('>L', data[offset:offset + 4])[0])
            offset += 8                                              # skip section offset and 'LINE'
            nwords_fname = unpack('>L', data[offset:offset + 4])[0]
            offset += 4
            log(DEBUG, "file name: %s", data[offset:offset + nwords_fname * 4].decode())
            nwords = nwords - nwords_fname - 3
            offset += nwords_fname * 4
            log(DEBUG, "outputting line table:")
            while nwords > 0:
                line = unpack('>L', data[offset:offset + 4])[0]
                offset += 4
                addr = unpack('>L', data[offset:offset + 4])[0]
                offset += 4
                log(DEBUG, "line #%d at address 0x%08x", line, addr)
                nwords -= 2
        else:
            log(DEBUG, "format is assumed to be STABS (GCC) - outputting stab table:")
            # With GCC, the stab table seems to start after 36 bytes in the HUNK_DEBUG hunk.
            # The first stab is N_SO (0x64), the offset seems to be the number of stabs that follow.
            offset += 36                                             # discard first 36 bytes
            stab    = Stab.from_buffer_copy(data[offset:])
            nstabs  = stab.st_offset                                 # offset of N_SO stab == number of stabs
            offset += sizeof(Stab)
            stabtab = data[offset:]                                  # stab table without first stab
            strtab  = data[offset + sizeof(Stab) * (nstabs - 1):]    # string table
            log(DEBUG, "stab: type = %s, string = '%s' (at 0x%x), other = 0x%x, desc = 0x%x, value = 0x%08x",
                HunkReader._stab_type_to_name[stab.st_type],
                HunkReader._get_string_from_buffer(strtab[stab.st_offset:]),
                stab.st_offset,
                stab.st_other,
                stab.st_desc,
                stab.st_value
            )

            offset  = 0
            for i in range(1, nstabs):
                stab = Stab.from_buffer_copy(stabtab[offset:])
                offset += sizeof(stab)
                if stab.st_type in HunkReader._stab_type_to_name:
                    log(DEBUG, "stab: type = %s, string = '%s' (at 0x%x), other = 0x%x, desc = 0x%x, value = 0x%08x",
                        HunkReader._stab_type_to_name[stab.st_type],
                        HunkReader._get_string_from_buffer(strtab[stab.st_offset:]),
                        stab.st_offset,
                        stab.st_other,
                        stab.st_desc,
                        stab.st_value
                    )
                elif stab.st_type & ~HunkReader.N_EXT in HunkReader._stab_type_to_name:
                    # stab contains external symbol => clear N_EXT bit to look up name
                    log(DEBUG, "stab: type = %s (external), string = '%s' (at 0x%x), other = 0x%x, desc = 0x%x, value = 0x%08x",
                        HunkReader._stab_type_to_name[stab.st_type & ~HunkReader.N_EXT],
                        HunkReader._get_string_from_buffer(strtab[stab.st_offset:]),
                        stab.st_offset,
                        stab.st_other,
                        stab.st_desc,
                        stab.st_value
                    )
                else:
                    log(ERROR, "stab with unknown type 0x%d found", stab.st_type)


    _read_funcs = dict()
    _read_funcs[HUNK_HEADER]  = _read_header_block
    _read_funcs[HUNK_UNIT]    = _read_unit_block
    _read_funcs[HUNK_NAME]    = _read_name_block
    _read_funcs[HUNK_CODE]    = _read_code_block
    _read_funcs[HUNK_DATA]    = _read_data_block
    _read_funcs[HUNK_BSS]     = _read_bss_block
    _read_funcs[HUNK_EXT]     = _read_ext_block
    _read_funcs[HUNK_SYMBOL]  = _read_symbol_block
    _read_funcs[HUNK_RELOC32] = _read_reloc32_block
    _read_funcs[HUNK_DEBUG]   = _read_debug_block



logging.basicConfig(level = DEBUG, format = '%(levelname)s: %(message)s')
reader = HunkReader(sys.argv[1])
reader.read()
