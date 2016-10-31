var util = require('util');
var Reader = require('endian-reader');

var macho = require('../macho');
var constants = macho.constants;

function Parser() {
  Reader.call(this);
};
util.inherits(Parser, Reader);
module.exports = Parser;

Parser.prototype.execute = function execute(buf) {
  var hdr = this.parseHead(buf);
  if (!hdr)
    throw new Error('File not in a mach-o format');

  hdr.cmds = this.parseCommands(hdr, hdr.body, buf);
  delete hdr.body;

  return hdr;
};

Parser.prototype.mapFlags = function mapFlags(value, map) {
  var res = {};

  for (var bit = 1; (value < 0 || bit <= value) && bit !== 0; bit <<= 1)
    if (value & bit)
      res[map[bit]] = true;

  return res;
};

Parser.prototype.parseHead = function parseHead(buf) {
  if (buf.length < 7 * 4)
    return false;

  var magic = buf.readUInt32LE(0);
  var bits;
  if (magic === 0xfeedface || magic === 0xcefaedfe)
    bits = 32;
  else if (magic === 0xfeedfacf || magic == 0xcffaedfe)
    bits = 64;
  else
    return false;

  if (magic & 0xff == 0xfe)
    this.setEndian('be');
  else
    this.setEndian('le');

  if (bits === 64 && buf.length < 8 * 4)
    return false;

  var cputype = constants.cpuType[this.readInt32(buf, 4)];
  var cpusubtype = this.readInt32(buf, 8);
  var filetype = this.readUInt32(buf, 12);
  var ncmds = this.readUInt32(buf, 16);
  var sizeofcmds = this.readUInt32(buf, 20);
  var flags = this.readUInt32(buf, 24);

  // Get endian
  var endian;
  if ((cpusubtype & constants.endian.multiple) === constants.endian.multiple)
    endian = 'multiple';
  else if (cpusubtype & constants.endian.be)
    endian = 'be';
  else
    endian = 'le';

  cpusubtype &= constants.cpuSubType.mask;

  // Get subtype
  var subtype;
  if (endian === 'multiple')
    subtype = 'all';
  else if (cpusubtype === 0)
    subtype = 'none';
  else
    subtype = constants.cpuSubType[cputype][cpusubtype];

  // Stringify flags
  var flagMap = this.mapFlags(flags, constants.flags);

  return {
    bits: bits,
    magic: magic,
    cpu: {
      type: cputype,
      subtype: subtype,
      endian: endian
    },
    filetype: constants.fileType[filetype],
    ncmds: ncmds,
    sizeofcmds: sizeofcmds,
    flags: flagMap,

    cmds: null,
    hsize: bits === 32 ? 28 : 32,
    body: bits === 32 ? buf.slice(28) : buf.slice(32)
  };
};

Parser.prototype.parseCommands = function parseCommands(hdr, buf, file) {
  var cmds = [];

  var align;
  if (hdr.bits === 32)
    align = 4;
  else
    align = 8;

  for (var offset = 0, i = 0; offset + 8 < buf.length, i < hdr.ncmds; i++) {
    var type = constants.cmdType[this.readUInt32(buf, offset)];
    var size = this.readUInt32(buf, offset + 4) - 8;

    var fileoff = offset + hdr.hsize;
    offset += 8;
    if (offset + size > buf.length)
      throw new Error('Command body OOB');

    var body = buf.slice(offset, offset + size);
    offset += size;
    if (offset & align)
      offset += align - (offset & align);

    var cmd = this.parseCommand(type, body, file);
    cmd.fileoff = fileoff;
    cmds.push(cmd);
  }

  return cmds;
};

Parser.prototype.parseCStr = function parseCStr(buf) {
  for (var i = 0; i < buf.length; i++)
    if (buf[i] === 0)
      break;
  return buf.slice(0, i).toString();
};

Parser.prototype.parseLCStr = function parseLCStr(buf, off) {
  if (off + 4 > buf.length)
    throw new Error('lc_str OOB');

  var offset = this.readUInt32(buf, off) - 8;
  if (offset > buf.length)
    throw new Error('lc_str offset OOB');

  return this.parseCStr(buf.slice(offset));
};

Parser.prototype.parseCommand = function parseCommand(type, buf, file) {
  if (type === 'segment')
    return this.parseSegmentCmd(type, buf, file);
  else if (type === 'segment_64')
    return this.parseSegmentCmd(type, buf, file);
  else if (type === 'symtab')
    return this.parseSymtab(type, buf);
  else if (type === 'symseg')
    return this.parseSymseg(type, buf);
  else if (type === 'encryption_info')
    return this.parseEncryptionInfo(type, buf);
  else if (type === 'encryption_info_64')
    return this.parseEncryptionInfo64(type, buf);
  else if (type === 'rpath')
    return this.parseRpath(type, buf);
  else if (type === 'dysymtab')
    return this.parseDysymtab(type, buf);
  else if (type === 'load_dylib' || type === 'id_dylib')
    return this.parseLoadDylib(type, buf);
  else if (type === 'load_weak_dylib')
    return this.parseLoadDylib(type, buf);
  else if (type === 'load_dylinker' || type === 'id_dylinker')
    return this.parseLoadDylinker(type, buf);
  else if (type === 'version_min_macosx' || type === 'version_min_iphoneos')
    return this.parseVersionMin(type, buf);
  else if (type === 'code_signature' || type === 'segment_split_info')
    return this.parseLinkEdit(type, buf);
  else if (type === 'function_starts')
    return this.parseFunctionStarts(type, buf, file);
  else if (type === 'data_in_code')
    return this.parseLinkEdit(type, buf);
  else if (type === 'dylib_code_sign_drs')
    return this.parseLinkEdit(type, buf);
  else if (type === 'main')
    return this.parseMain(type, buf);
  else
    return { type: type, data: buf };
};

Parser.prototype.parseSegmentCmd = function parseSegmentCmd(type, buf, file) {
  var total = type === 'segment' ? 48 : 64;
  if (buf.length < total)
    throw new Error('Segment command OOB');

  var name = this.parseCStr(buf.slice(0, 16));

  if (type === 'segment') {
    var vmaddr = this.readUInt32(buf, 16);
    var vmsize = this.readUInt32(buf, 20);
    var fileoff = this.readUInt32(buf, 24);
    var filesize = this.readUInt32(buf, 28);
    var maxprot = this.readUInt32(buf, 32);
    var initprot = this.readUInt32(buf, 36);
    var nsects = this.readUInt32(buf, 40);
    var flags = this.readUInt32(buf, 44);
  } else {
    var vmaddr = this.readUInt64(buf, 16);
    var vmsize = this.readUInt64(buf, 24);
    var fileoff = this.readUInt64(buf, 32);
    var filesize = this.readUInt64(buf, 40);
    var maxprot = this.readUInt32(buf, 48);
    var initprot = this.readUInt32(buf, 52);
    var nsects = this.readUInt32(buf, 56);
    var flags = this.readUInt32(buf, 60);
  }

  function prot(p) {
    var res = { read: false, write: false, exec: false };
    if (p !== constants.prot.none) {
      res.read = (p & constants.prot.read) !== 0;
      res.write = (p & constants.prot.write) !== 0;
      res.exec = (p & constants.prot.execute) !== 0;
    }
    return res;
  }

  var sectSize = type === 'segment' ? 32 + 9 * 4 : 32 + 8 * 4 + 2 * 8;
  var sections = [];
  for (var i = 0, off = total; i < nsects; i++, off += sectSize) {
    if (off + sectSize > buf.length)
      throw new Error('Segment OOB');

    var sectname = this.parseCStr(buf.slice(off, off + 16));
    var segname = this.parseCStr(buf.slice(off + 16, off + 32));

    if (type === 'segment') {
      var addr = this.readUInt32(buf, off + 32);
      var size = this.readUInt32(buf, off + 36);
      var offset = this.readUInt32(buf, off + 40);
      var align = this.readUInt32(buf, off + 44);
      var reloff = this.readUInt32(buf, off + 48);
      var nreloc = this.readUInt32(buf, off + 52);
      var flags = this.readUInt32(buf, off + 56);
    } else {
      var addr = this.readUInt64(buf, off + 32);
      var size = this.readUInt64(buf, off + 40);
      var offset = this.readUInt32(buf, off + 48);
      var align = this.readUInt32(buf, off + 52);
      var reloff = this.readUInt32(buf, off + 56);
      var nreloc = this.readUInt32(buf, off + 60);
      var flags = this.readUInt32(buf, off + 64);
    }

    sections.push({
      sectname: sectname,
      segname: segname,
      addr: addr,
      size: size,
      offset: offset,
      align: align,
      reloff: reloff,
      nreloc: nreloc,
      type: constants.segType[flags & constants.segTypeMask],
      attributes: {
        usr: this.mapFlags(flags & constants.segAttrUsrMask,
                           constants.segAttrUsr),
        sys: this.mapFlags(flags & constants.segAttrSysMask,
                           constants.segAttrSys)
      },
      data: file.slice(offset, offset + size)
    });
  }

  return {
    type: type,
    name: name,
    vmaddr: vmaddr,
    vmsize: vmsize,
    fileoff: fileoff,
    filesize: filesize,
    maxprot: prot(maxprot),
    initprot: prot(initprot),
    nsects: nsects,
    flags: this.mapFlags(flags, constants.segFlag),
    sections: sections
  };
};

Parser.prototype.parseSymtab = function parseSymtab(type, buf) {
  if (buf.length !== 16)
    throw new Error('symtab OOB');

  return {
    type: type,
    symoff: this.readUInt32(buf, 0),
    nsyms: this.readUInt32(buf, 4),
    stroff: this.readUInt32(buf, 8),
    strsize: this.readUInt32(buf, 12)
  };
};

Parser.prototype.parseSymseg = function parseSymseg(type, buf) {
  if (buf.length !== 8)
    throw new Error('symseg OOB');

  return {
    type: type,
    offset: this.readUInt32(buf, 0),
    size: this.readUInt32(buf, 4)
  };
};

Parser.prototype.parseEncryptionInfo = function parseEncryptionInfo(type, buf) {
  if (buf.length !== 12)
    throw new Error('encryptinfo OOB');

  return {
    type: type,
    offset: this.readUInt32(buf, 0),
    size: this.readUInt32(buf, 4),
    id: this.readUInt32(buf, 8),
  };
};

Parser.prototype.parseEncryptionInfo64 = function parseEncryptionInfo64(type, buf) {
  if (buf.length !== 16)
    throw new Error('encryptinfo64 OOB');

  return this.parseEncryptionInfo(type, buf.slice(0, 12));
};

Parser.prototype.parseDysymtab = function parseDysymtab(type, buf) {
  if (buf.length !== 72)
    throw new Error('dysymtab OOB');

  return {
    type: type,
    ilocalsym: this.readUInt32(buf, 0),
    nlocalsym: this.readUInt32(buf, 4),
    iextdefsym: this.readUInt32(buf, 8),
    nextdefsym: this.readUInt32(buf, 12),
    iundefsym: this.readUInt32(buf, 16),
    nundefsym: this.readUInt32(buf, 20),
    tocoff: this.readUInt32(buf, 24),
    ntoc: this.readUInt32(buf, 28),
    modtaboff: this.readUInt32(buf, 32),
    nmodtab: this.readUInt32(buf, 36),
    extrefsymoff: this.readUInt32(buf, 40),
    nextrefsyms: this.readUInt32(buf, 44),
    indirectsymoff: this.readUInt32(buf, 48),
    nindirectsyms: this.readUInt32(buf, 52),
    extreloff: this.readUInt32(buf, 56),
    nextrel: this.readUInt32(buf, 60),
    locreloff: this.readUInt32(buf, 64),
    nlocrel: this.readUInt32(buf, 68)
  };
};

Parser.prototype.parseLoadDylinker = function parseLoadDylinker(type, buf) {
  return {
    type: type,
    cmd: this.parseLCStr(buf, 0)
  };
};

Parser.prototype.parseRpath = function parseRpath (type, buf) {
  if (buf.length < 8)
    throw new Error('lc_rpath OOB');

  return {
    type: type,
    name: this.parseLCStr(buf, 0),
  };
};

Parser.prototype.parseLoadDylib = function parseLoadDylib(type, buf) {
  if (buf.length < 16)
    throw new Error('load_dylib OOB');

  return {
    type: type,
    name: this.parseLCStr(buf, 0),
    timestamp: this.readUInt32(buf, 4),
    current_version: this.readUInt32(buf, 8),
    compatibility_version: this.readUInt32(buf, 12)
  };
};

Parser.prototype.parseVersionMin = function parseVersionMin(type, buf) {
  if (buf.length !== 8)
    throw new Error('min version OOB');

  return {
    type: type,
    version: this.readUInt16(buf, 2) + '.' + buf[1] + '.' + buf[0],
    sdk: this.readUInt16(buf, 6) + '.' + buf[5] + '.' + buf[4]
  };
};

Parser.prototype.parseLinkEdit = function parseLinkEdit(type, buf) {
  if (buf.length !== 8)
    throw new Error('link_edit OOB');

  return {
    type: type,
    dataoff: this.readUInt32(buf, 0),
    datasize: this.readUInt32(buf, 4)
  };
};

// NOTE: returned addresses are relative to the "base address", i.e.
//       the vmaddress of the first "non-null" segment [e.g. initproto!=0]
//       (i.e. __TEXT ?)
Parser.prototype.parseFunctionStarts = function parseFunctionStarts(type,
                                                                    buf,
                                                                    file) {
  if (buf.length !== 8)
    throw new Error('function_starts OOB');

  var dataoff = this.readUInt32(buf, 0);
  var datasize = this.readUInt32(buf, 4);
  var data = file.slice(dataoff, dataoff + datasize);

  var addresses = [];
  var address = 0; // TODO? use start address / "base address"

  // read array of uleb128-encoded deltas
  var delta = 0, shift = 0;
  for (var i = 0; i < data.length; i++) {
    delta |= (data[i] & 0x7f) << shift;
    if ((data[i] & 0x80) !== 0) { // delta value not finished yet
      shift += 7;
      if (shift > 24)
        throw new Error('function_starts delta too large');
      else if (i + 1 === data.length)
        throw new Error('function_starts delta truncated');
    } else if (delta === 0) { // end of table
      break;
    } else {
      address += delta;
      addresses.push(address);
      delta = 0;
      shift = 0;
    }
  }

  return {
    type: type,
    dataoff: dataoff,
    datasize: datasize,
    addresses: addresses
  };
};

Parser.prototype.parseMain = function parseMain(type, buf) {
  if (buf.length < 16)
    throw new Error('main OOB');

  return {
    type: type,
    entryoff: this.readUInt64(buf, 0),
    stacksize: this.readUInt64(buf, 8)
  };
};
