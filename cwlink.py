#!/usr/bin/env python3


import sys
import logging
from logging import log, DEBUG, INFO, WARN, ERROR, CRITICAL
from struct import pack, unpack
from argparse import ArgumentParser
from collections import namedtuple
from recordclass import recordclass


# std::string hexdump (const uint8_t *buffer, size_t length)
# {
#     std::string dump;
#     size_t pos = 0;
# 
#     while (pos < length)
#     {
#         dump += Poco::format ("%04?x: ", pos);
#         std::string line;
#         for (size_t i = pos; (i < pos + 16) && (i < length); i++)
#         {
#             dump += Poco::format ("%02?x ", buffer[i]);
#             if (buffer[i] >= 0x20 && buffer[i] <= 0x7e)
#             {
#                 line.append (1, buffer[i]);
#             }
#             else
#             {
#                 line.append (1, '.');
#             }
#         }
#         if (line.size() < 16)
#             dump.append (3 * (16 - line.size()), ' ');
# 
#         dump.append (1, '\t');
#         dump += line;
#         dump.append (1, '\n');
#         pos += 16;
#     }
#     return dump;
# }


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
        self._fname = fname
        self._hunks = list()


    def read(self):
        with open(self._fname, 'rb') as self._fobj:
            hnum = 0
            while True:
                try:
                    btype = self._read_word()
                    log(DEBUG, "hunk #%d, block type = 0x%04x (%d)", hnum, btype, btype)
                    if btype == HunkReader.HUNK_END:
                        # possibly another hunk follows, nothing else to do
                        log(DEBUG, "hunk #%d finished", hnum)
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
                
                
    def get_hunks(self):
        return self._hunks.__iter__()
    
    
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
        self._ftype = HunkReader.FILE_EXE
        # In an executable the hunks don't have names...
        self._name = ''
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
        self._ftype = HunkReader.FILE_OBJ
        self.uname  = self._read_string(self._read_word() * 4)
        log(INFO, "unit name: %s", self.uname)
        
        
    def _read_name_block(self):
        log(INFO, "reading HUNK_NAME block...")
        # A HUNK_NAME block always starts a new hunk, but we don't know yet what kind of hunk it will be,
        # so we just store the name for now.
        self._hname = self._read_string(self._read_word() * 4)
        log(INFO, "hunk name: %s", self._hname)
        
        
    def _read_code_block(self):
        log(INFO, "reading HUNK_CODE block...")
        nwords = self._read_word()
        log(DEBUG, "size (in bytes) of code block: %d", nwords * 4)
        self._hunks.append(CodeHunk(self._hname, self._fobj.read(nwords * 4)))
        
        
    def _read_data_block(self):
        log(INFO, "reading HUNK_DATA block...")
        nwords = self._read_word()
        log(DEBUG, "size (in bytes) of data block: %d", nwords * 4)
        # Both the AmigaDOS manual and the Amiga Guru book say that after the length word only the data
        # itself and nothing else follows, but it seems in executables there always comes a zero word
        # after the data...
        if self._ftype == HunkReader.FILE_EXE:
            self._hunks.append(DataHunk(self._hname, self._fobj.read((nwords + 1) * 4)))
        else:
            self._hunks.append(DataHunk(self._hname, self._fobj.read(nwords * 4)))
        
        
    def _read_bss_block(self):
        log(INFO, "reading HUNK_BSS block...")
        nwords = self._read_word()
        log(DEBUG, "size (in bytes) of BSS block: %d", nwords * 4)
        self._hunks.append(BSSHunk(self._hname, nwords * 4))
        
        
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
                sval = self._read_word()
                log(DEBUG, "definition of symbol (type = %d): %s = 0x%08x", stype, sname, sval)
                self._hunks[-1].add_symbol(sname, sval)
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



class Hunk(object):
    def __init__(self):
        self._symbols = dict()
        
        
    def add_symbol(self, sname, sval):
        self._symbols[sname] = sval
        
        
    def get_symbols(self):
        return self._symbols.items()



class CodeHunk(Hunk):
    def __init__(self, name, code):
        Hunk.__init__(self)
        self.name = name
        self.code = code
        self.size = len(code)
        
        
    def __repr__(self):
        return "CodeHunk[name = %s, size = %d]" % (self.name, self.size)
    
    
    def merge_hunk(self, hunk):
        offset = self.size
        self.code += hunk.code
        self.size = len(self.code)
    
    

class DataHunk(Hunk):
    def __init__(self, name, data):
        Hunk.__init__(self)
        self.name = name
        self.data = data
        self.size = len(data)


    def __repr__(self):
        return "DataHunk[name = %s, size = %d]" % (self.name, self.size)



class BSSHunk(Hunk):
    def __init__(self, name, size):
        Hunk.__init__(self)
        self.name = name
        self.size = size


    def __repr__(self):
        return "BSSHunk[name = %s, size = %d]" % (self.name, self.size)



# types for the global database
HunkEntry = recordclass('HunkEntry', ('hnum', 'offset', 'hunks'))
SymEntry  = namedtuple('SymEntry', ('uname', 'hname', 'value'))



parser = ArgumentParser(description = 'Simple linker for AmigaOS')
parser.add_argument('-o', dest = 'ofname', type = str, help = 'name of output file (executable)')
parser.add_argument('-v', dest = 'verbose', action = 'store_true', help = 'verbose output')
parser.add_argument('files', nargs = '*', help = 'object file(s)')
args = parser.parse_args()
if args.verbose:
    level = DEBUG
else:
    level = INFO
logging.basicConfig(level = level, format = '%(levelname)s: %(message)s')

# build symbol database and map of executable => mapping of unit + hunk name to hunk number + offset
hunklist = dict()
hunkmap  = dict()
symlist  = dict()
nhunks   = 0
for fname in args.files:
    log(INFO, "reading object file %s", fname)
    reader = HunkReader(fname)
    reader.read()
    
    for hunk in reader.get_hunks():
        log(INFO, "determining where the hunk %s will be located in the executable...", hunk.name)
        source = reader.uname + ':' + hunk.name
        # Does a hunk with the same name already exist?
        if hunk.name in hunklist:
            # yes => We can merge the hunks, so we add the hunk to the list. We take the size of the
            # existing hunk(s) as offset and add our own size.
            hunklist[hunk.name].hunks.append(hunk)
            target = str(hunklist[hunk.name].hnum) + ':' + str(hunklist[hunk.name].offset)
            hunklist[hunk.name].offset += hunk.size
        else:
            # no  => We create a new list of hunks, offset is 0, and set our own size as offset
            # for any following hunk with the same name
            hunklist[hunk.name] = HunkEntry(nhunks, hunk.size, [hunk])
            target = str(hunklist[hunk.name].hnum) + ':' + '0'
            nhunks += 1
        hunkmap[source] = target
        
        log(INFO, "adding symbols to global database...")
        for sname, sval in hunk.get_symbols():
            symlist[sname] = SymEntry(reader.uname, hunk.name, str(sval))
        

print(hunkmap)
print(symlist)
