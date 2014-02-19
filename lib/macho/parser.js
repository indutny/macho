var macho = require('../macho');
var constants = macho.constants;

function Parser() {
};
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
  if (magic === 0xfeedface)
    bits = 32;
  else if (magic === 0xfeedfacf)
    bits = 64;
  else
    return false;

  if (bits === 64 && buf.length < 8 * 4)
    return false;

  var cputype = constants.cpuType[buf.readInt32LE(4)];
  var cpusubtype = buf.readInt32LE(8);
  var filetype = buf.readUInt32LE(12);
  var ncmds = buf.readUInt32LE(16);
  var sizeofcmds = buf.readUInt32LE(20);
  var flags = buf.readUInt32LE(24);

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
  if (endian === 'mutliple')
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
    var type = constants.cmdType[buf.readUInt32LE(offset)];
    var size = buf.readUInt32LE(offset + 4) - 8;

    offset += 8;
    if (offset + size > buf.length)
      throw new Error('Command body OOB');

    var body = buf.slice(offset, offset + size);
    offset += size;
    if (offset & align)
      offset += align - (offset & align);

    cmds.push(this.parseCommand(type, body, file));
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

  var offset = buf.readUInt32LE(off) - 8;
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
  else if (type === 'function_starts' || type === 'data_in_code')
    return this.parseLinkEdit(type, buf);
  else if (type === 'dylib_code_sign_drs')
    return this.parseLinkEdit(type, buf);
  else
    return { type: type, data: buf };
};

Parser.prototype.parseSegmentCmd = function parseSegmentCmd(type, buf, file) {
  var total = type === 'segment' ? 48 : 64;
  if (buf.length < total)
    throw new Error('Segment command OOB');

  var name = this.parseCStr(buf.slice(0, 16));

  if (type === 'segment') {
    var vmaddr = buf.readUInt32LE(16);
    var vmsize = buf.readUInt32LE(20);
    var fileoff = buf.readUInt32LE(24);
    var filesize = buf.readUInt32LE(28);
    var maxprot = buf.readUInt32LE(32);
    var initprot = buf.readUInt32LE(36);
    var nsects = buf.readUInt32LE(40);
    var flags = buf.readUInt32LE(44);
  } else {
    var vmaddr = buf.slice(16, 24);
    var vmsize = buf.slice(24, 32);
    var fileoff = buf.slice(32, 40);
    var filesize = buf.slice(40, 48);
    var maxprot = buf.readUInt32LE(48);
    var initprot = buf.readUInt32LE(52);
    var nsects = buf.readUInt32LE(56);
    var flags = buf.readUInt32LE(60);
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
      var addr = buf.readUInt32LE(off + 32);
      var size = buf.readUInt32LE(off + 36);
      var offset = buf.readUInt32LE(off + 40);
      var align = buf.readUInt32LE(off + 44);
      var reloff = buf.readUInt32LE(off + 48);
      var nreloc = buf.readUInt32LE(off + 52);
      var flags = buf.readUInt32LE(off + 56);
    } else {
      var addr = buf.slice(off + 32, off + 40);
      var size = buf.slice(off + 40, off + 48);
      var offset = buf.readUInt32LE(off + 48);
      var align = buf.readUInt32LE(off + 52);
      var reloff = buf.readUInt32LE(off + 56);
      var nreloc = buf.readUInt32LE(off + 60);
      var flags = buf.readUInt32LE(off + 64);
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
    symoff: buf.readUInt32LE(0),
    nsyms: buf.readUInt32LE(4),
    stroff: buf.readUInt32LE(8),
    strsize: buf.readUInt32LE(12)
  };
};

Parser.prototype.parseSymseg = function parseSymseg(type, buf) {
  if (buf.length !== 8)
    throw new Error('symseg OOB');

  return {
    type: type,
    offset: buf.readUInt32LE(0),
    size: buf.readUInt32LE(4)
  };
};

Parser.prototype.parseDysymtab = function parseDysymtab(type, buf) {
  if (buf.length !== 72)
    throw new Error('dysymtab OOB');

  return {
    type: type,
    ilocalsym: buf.readUInt32LE(0),
    nlocalsym: buf.readUInt32LE(4),
    iextdefsym: buf.readUInt32LE(8),
    nextdefsym: buf.readUInt32LE(12),
    iundefsym: buf.readUInt32LE(16),
    nundefsym: buf.readUInt32LE(20),
    tocoff: buf.readUInt32LE(24),
    ntoc: buf.readUInt32LE(28),
    modtaboff: buf.readUInt32LE(32),
    nmodtab: buf.readUInt32LE(36),
    extrefsymoff: buf.readUInt32LE(40),
    nextrefsyms: buf.readUInt32LE(44),
    indirectsymoff: buf.readUInt32LE(48),
    nindirectsyms: buf.readUInt32LE(52),
    extreloff: buf.readUInt32LE(56),
    nextrel: buf.readUInt32LE(60),
    locreloff: buf.readUInt32LE(64),
    nlocrel: buf.readUInt32LE(68)
  };
};

Parser.prototype.parseLoadDylinker = function parseLoadDylinker(type, buf) {
  return {
    type: type,
    cmd: this.parseLCStr(buf, 0)
  };
};

Parser.prototype.parseLoadDylib = function parseLoadDylib(type, buf) {
  if (buf.length < 16)
    throw new Error('load_dylib OOB');

  return {
    type: type,
    name: this.parseLCStr(buf, 0),
    timestamp: buf.readUInt32LE(4),
    current_version: buf.readUInt32LE(8),
    compatibility_version: buf.readUInt32LE(12)
  };
};

Parser.prototype.parseVersionMin = function parseVersionMin(type, buf) {
  if (buf.length !== 8)
    throw new Error('min version OOB');

  return {
    type: type,
    version: buf.readUInt16LE(2) + '.' + buf[1] + '.' + buf[0],
    sdk: buf.readUInt16LE(6) + '.' + buf[5] + '.' + buf[4]
  };
};

Parser.prototype.parseLinkEdit = function parseLinkEdit(type, buf) {
  if (buf.length !== 8)
    throw new Error('link_edit OOB');

  return {
    type: type,
    dataoff: buf.readUInt32LE(0),
    datasize: buf.readUInt32LE(4)
  };
};
