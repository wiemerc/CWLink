#!/usr/bin/env python3



import sys
import logging
from logging import log, DEBUG, INFO, WARN, ERROR, CRITICAL
from struct import pack, unpack
from argparse import ArgumentParser
from collections import namedtuple, OrderedDict
from recordclass import recordclass
from enum import IntEnum



#
# data structures
#
# TODO: Maybe we should use a class for the database?
# We build a global database from the object files. The structure of the database looks like this:
# hunks
# |
# --- code
# |   |
# |   --- <name>
# |       |
# |       --- hunk (unit name, content, references, relocations)
# --- data
# |   |
# |   --- <name>
# |       |
# |       --- hunk (unit name, content)
# --- bss
#     |
#     --- <name>
#         |
#         --- hunk (unit name)
# symbols
# |
# --- <name>
#     |
#     --- symbol (unit name, hunk type, hunk name, offset)

Hunk      = recordclass('Hunk', ('uname', 'content', 'refs', 'relocs'))
Symbol    = recordclass('Symbol', ('uname', 'htype', 'hname', 'offset'))
Reloc     = recordclass('Reloc', ('uname', 'htype', 'hname', 'hnum', 'offset'))
Reference = recordclass('Reference', ('sname', 'type', 'offset'))
DataBase  = recordclass('DataBase', ('hunks', 'symbols', 'map'))

db = DataBase(hunks = {'code': {}, 'data': {}, 'bss': {}}, symbols = {}, map = {})



# block types from from dos/doshunks.h
class BlockType(IntEnum):
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
    


class ExtType(IntEnum):
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
        
    

class HunkReader(object):
    
    def __init__(self, fname, db):
        self._fname = fname
        self._db    = db


    def read(self):
        with open(self._fname, 'rb') as self._fobj:
            
            hnum = 0
            htype_hname = {}
            while True:
                try:
                    btype = self._read_word()
                    log(DEBUG, "reading hunk #%d, block %s (%d)", hnum, BlockType(btype), btype)
                    
                    if btype == BlockType.HUNK_UNIT:
                        uname = self._read_string(self._read_word() * 4)
                        log(DEBUG, "unit name: %s", uname)
                        
                    elif btype == BlockType.HUNK_NAME:
                        hname = self._read_string(self._read_word() * 4)
                        log(DEBUG, "hunk name: %s", hname)
                        
                    elif btype == BlockType.HUNK_CODE:
                        nwords = self._read_word()
                        log(DEBUG, "size (in bytes) of code block: %d", nwords * 4)
                        htype = 'code'
                        hunk  = Hunk(uname, self._fobj.read(nwords * 4), [], [])
                        if hname not in db.hunks['code']:
                            self._db.hunks['code'][hname] = []
                        self._db.hunks['code'][hname].append(hunk)
                        
                    elif btype == BlockType.HUNK_RELOC32:
                        while True:
                            noffsets = self._read_word()
                            if noffsets == 0:
                                break
                            
                            refhnum = self._read_word()
                            log(DEBUG, "relocations referencing hunk #%d:", refhnum)
                            for i in range(0, noffsets):
                                offset = self._read_word()
                                log(DEBUG, "offset = 0x%08x", offset)
                                hunk.relocs.append(Reloc(uname, '', '', refhnum, offset))
                        
                    elif btype == BlockType.HUNK_EXT:
                        while True:
                            type_len = self._read_word()
                            if type_len == 0:
                                break
                            
                            stype = (type_len & 0xff000000) >> 24
                            sname = self._read_string((type_len & 0x00ffffff) * 4)
                            
                            if stype in (ExtType.EXT_DEF, ExtType.EXT_ABS, ExtType.EXT_RES):
                                # definition
                                # TODO: What about EXT_ABS and EXT_RES?
                                sval = self._read_word()
                                log(DEBUG, "definition of symbol (type = %d): %s = 0x%08x", stype, sname, sval)
                                self._db.symbols[sname] = Symbol(uname, htype, hname, sval)
                            elif stype in (ExtType.EXT_REF8, ExtType.EXT_REF16, ExtType.EXT_REF32):
                                # reference(s)
                                nrefs = self._read_word()
                                for i in range(0, nrefs):
                                    offset = self._read_word()
                                    log(DEBUG, "reference to symbol %s (type = %d): 0x%08x", sname, stype, offset)
                                    hunk.refs.append(Reference(sname, stype, offset))
                            else:
                                log(ERROR, "symbol type %d not supported", stype)
                        
                    elif btype == BlockType.HUNK_DATA:
                        nwords = self._read_word()
                        log(DEBUG, "size (in bytes) of data block: %d", nwords * 4)
                        htype = 'data'
                        hunk  = Hunk(uname, self._fobj.read(nwords * 4), [], [])
                        if hname not in db.hunks['data']:
                            self._db.hunks['data'][hname] = []
                        self._db.hunks['data'][hname].append(hunk)
                        
                    elif btype == BlockType.HUNK_BSS:
                        nwords = self._read_word()
                        log(DEBUG, "size (in bytes) of BSS block: %d", nwords * 4)
                        htype = 'bss'
                        hunk  = Hunk(uname, '', [], [])
                        if hname not in db.hunks['bss']:
                            self._db.hunks['bss'][hname] = []
                        self._db.hunks['bss'][hname].append(hunk)
                        
                    elif btype == BlockType.HUNK_SYMBOL:
                        while True:
                            nwords = self._read_word()
                            if nwords == 0:
                                break
            
                            sname = self._read_string(nwords * 4)
                            sval  = self._read_word()
                            log(DEBUG, "symbol %s = 0x%08x", sname, sval)
                        
                    elif btype == BlockType.HUNK_END:
                        log(DEBUG, "hunk #%d finished", hnum)
                        # We need to store the hunk type and name together for the hunk number so that we can
                        # normalize the relocations later
                        htype_hname[hnum] = htype + ':' + hname
                        hnum += 1
                        
                    else:
                        log(ERROR, "block type %s not known or implemented", ex)
                        break
                        
                except EOFError:
                    if btype == BlockType.HUNK_END:
                        # Once we have read all the hunks in this unit, we can normalize the relocations
                        log(DEBUG, "normalizing relocations...")
                        for hname in self._db.hunks['code']:
                            for hunk in self._db.hunks['code'][hname]:
                                if hunk.uname != uname:
                                    # only the hunks from this unit
                                    continue
                                for reloc in hunk.relocs:
                                    refhtype, refhname = htype_hname[reloc.hnum].split(':')
                                    reloc.htype = refhtype
                                    reloc.hname = refhname
                        return
                    else:
                        log(ERROR, "encountered EOF while reading file '%s'", self.fname)
                        return
    
    
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
        
        
        
class HunkWriter(object):
    def __init__(self, fname, db):
        self._fname = fname
        self._db    = db
        
        
    def write(self):
        pass
    
    
    
#
# main program
#
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


# read object files and build database
# TODO: The read() method could return a database for the object file and we could merge these partial databases.
for fname in args.files:
    log(INFO, "reading object file %s...", fname)
    reader = HunkReader(fname, db)
    reader.read()


# resolve references to relocations
log(INFO, "resolving references...")
for hname in db.hunks['code']:
    for hunk in db.hunks['code'][hname]:
        log(DEBUG, "processing hunk %s in unit %s...", hname, hunk.uname)
        for ref in hunk.refs:
            if ref.sname in db.symbols:
                sym   = db.symbols[ref.sname]
                reloc = Reloc(sym.uname, sym.htype, sym.hname, -1, sym.offset)
                log(DEBUG, "adding relocation %s for referenced symbol %s", reloc, ref.sname)
                hunk.relocs.append(reloc)
            else:
                log(ERROR, "undefined symbol %s", ref.sname)


# build map of executable => mapping of unit name + hunk type + hunk name to hunk number + displacement
# We assume here that in each unit there exists only *one* hunk with a certain type / name combination. I don't know
# if this is always the case...
log(INFO, "building map of executable...")
hnum = 0
for htype in ('code', 'data', 'bss'):
    for hname in db.hunks[htype]:
        disp = 0
        for hunk in db.hunks[htype][hname]:
            source = hunk.uname + ':' + htype + ':' + hname
            target = str(hnum) + ':' + str(disp)
            log(DEBUG, "mapping hunk %s to %s", source, target)
            db.map[source] = target
            disp += len(hunk.content)
        hnum += 1
            

# write executable
log(INFO, "writing executable %s...", args.ofname)
writer = HunkWriter(args.ofname, db)
writer.write()
