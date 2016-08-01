#!/usr/bin/env python3



import sys
import logging
from logging import log, DEBUG, INFO, WARN, ERROR, CRITICAL
from struct import pack, unpack



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

    
    
    def _read_header_block(self):
        log(INFO, "reading HUNK_HEADER block... file is a AmigaDOS executable")
        self.ftype = HunkReader.FILE_EXE
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
        self.ftype = HunkReader.FILE_OBJ
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
        # Both the AmigaDOS manual and the Amiga Guru book state that after the length word only the data
        # itself and nothing else follows, but it seems in executables the data is always followed by a null word...
        # TODO: create hexdump with the symbols, references and addresses to be relocated highlighted
        if self.ftype == HunkReader.FILE_EXE:
            log(DEBUG, "hex dump of code block:\n" + hexdump(self._fobj.read((nwords  + 1) * 4)))
        else:
            log(DEBUG, "hex dump of code block:\n" + hexdump(self._fobj.read(nwords * 4)))
        
        
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
                log(ERROR, "symbol type %d not supported", stype)
        
        
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
                log(DEBUG, "offset = 0x%08x", self._read_word())
            
        
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



logging.basicConfig(level = DEBUG, format = '%(levelname)s: %(message)s')
reader = HunkReader(sys.argv[1])
reader.read()
