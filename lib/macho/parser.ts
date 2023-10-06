import { Reader } from "./endian-reader.js";
import { constants } from "./constants.js";
import Buffer from "buffer";

export class Parser extends Reader {
    execute(buf: Buffer) : Header {
        var hdr = this.parseHead(buf);
        if (typeof hdr === "boolean") {
            if (hdr === false) {
                throw new Error('File not in a mach-o format');
            }
            throw new Error("Unhandled case");
        }
        hdr.cmds = this.parseCommands(hdr, hdr.body, buf);
        delete hdr.body;
        return hdr;
    }

    parseLCStr(buf: Buffer, off: number): string {
        if (off + 4 > buf.length) {
            throw new Error("lc_str OOB");
        }
        const offset = super.readUInt32(buf, off) - 8;
        if (offset > buf.length) {
            throw new Error("lc_str offset OOB");
        }
        return this.parseCStr(buf.subarray(offset));
    }

    // TODO return null or optional instead of the original boolean
    parseHead(buf: Buffer): Header | boolean {
        if (buf.length < 7 * 4) {
            return false;
        }

        const magic = buf.readUInt32LE(0);
        let bits = -1;
        switch (magic) {
            case 0xfeedface:
            case 0xcefaedfe:
                bits = 32;
                break;
            case 0xfeedfacf:
            case 0xcffaedfe:
                bits = 64;
                break;
            default:
                return false;
        }

        const endianType = ((magic & 0xff) == 0xfe)? "be": "le";
        super.setEndian(endianType);

        if (bits === 64 && buf.length < 8 * 4) {
            return false;
        }

        const cputype = constants.cpuType[super.readInt32(buf, 4)];
        let cpusubtype = super.readInt32(buf, 8);
        const filetype = super.readUInt32(buf, 12);
        const ncmds = super.readUInt32(buf, 16);
        const sizeofcmds = super.readUInt32(buf, 20);
        const flags = super.readUInt32(buf, 24);

        // Get endian
        const endian = endianFromCpu(cpusubtype);
        cpusubtype &= constants.cpuSubType.mask;

        // Get subtype
        const subtype = subtypeFromCpu(endian, cputype, cpusubtype);

        // Stringify flags
        const flagMap = this.mapFlags(flags, constants.flags);

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
            body: bits === 32 ? buf.subarray(28) : buf.subarray(32)
        };
    }

    parseMain(type: string, buf: Buffer): Main {
        if (buf.length < 16) {
            throw new Error('main OOB');
        }
        return {
            type: type,
            entryoff: super.readUInt64(buf, 0),
            stacksize: super.readUInt64(buf, 8)
        };
    }

    mapFlags(value: number, map: any): object {
        const res: any = {};
        for (let bit = 1; (value < 0 || bit <= value) && bit !== 0; bit <<= 1) {
            if (value & bit) {
                res[map[bit]] = true;
            }
        }
        return res;
    }

    parseCommands(hdr: any, buf: any, file: any) {
        const cmds: any[] = [];
        const align: number = (hdr.bits === 32) ? 4 : 8;

        for (let offset = 0, i = 0; offset + 8 < buf.length, i < hdr.ncmds; i++) {
            const type = constants.cmdType[super.readUInt32(buf, offset)];
            const size = super.readUInt32(buf, offset + 4) - 8;

            let fileoff = offset + hdr.hsize;
            offset += 8;
            if (offset + size > buf.length) {
                throw new Error('Command body OOB');
            }
            const body = buf.subarray(offset, offset + size);
            offset += size;
            if (offset & align) {
                offset += align - (offset & align);
            }
            const cmd: any = this.parseCommand(type, body, file);
            cmd.fileoff = fileoff;
            cmds.push(cmd);
        }

        return cmds;
    }

    parseFunctionStarts(type: any, buf: any, file: any): FunctionStart {
        if (buf.length !== 8) {
            throw new Error('function_starts OOB');
        }

        const dataoff = super.readUInt32(buf, 0);
        const datasize = super.readUInt32(buf, 4);
        const data = file.subarray(dataoff, dataoff + datasize);

        const addresses = [];
        let address = 0; // TODO? use start address / "base address"

        // read array of uleb128-encoded deltas
        let delta = 0;
        let shift = 0;
        for (let i = 0; i < data.length; i++) {
            delta |= (data[i] & 0x7f) << shift;
            if ((data[i] & 0x80) !== 0) { // delta value not finished yet
                shift += 7;
                if (shift > 24) {
                    throw new Error('function_starts delta too large');
                }
                if (i + 1 === data.length) {
                    throw new Error('function_starts delta truncated');
                }
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
    }

    parseSegmentCmd(type: any, buf: any, file: any): SegmentCmd {
        const total = (type === "segment") ? 48 : 64;
        if (buf.length < total) {
            throw new Error('Segment command OOB');
        }

        const name = this.parseCStr(buf.subarray(0, 16));

        if (type === "segment") {
            var vmaddr = super.readUInt32(buf, 16);
            var vmsize = super.readUInt32(buf, 20);
            var fileoff = super.readUInt32(buf, 24);
            var filesize = super.readUInt32(buf, 28);
            var maxprot = super.readUInt32(buf, 32);
            var initprot = super.readUInt32(buf, 36);
            var nsects = super.readUInt32(buf, 40);
            var flags = super.readUInt32(buf, 44);
        } else {
            var vmaddr = super.readUInt64(buf, 16);
            var vmsize = super.readUInt64(buf, 24);
            var fileoff = super.readUInt64(buf, 32);
            var filesize = super.readUInt64(buf, 40);
            var maxprot = super.readUInt32(buf, 48);
            var initprot = super.readUInt32(buf, 52);
            var nsects = super.readUInt32(buf, 56);
            var flags = super.readUInt32(buf, 60);
        }

        function prot(p: any): Protection {
            const res = { read: false, write: false, exec: false };
            if (p !== constants.prot.none) {
                res.read = (p & constants.prot.read) !== 0;
                res.write = (p & constants.prot.write) !== 0;
                res.exec = (p & constants.prot.execute) !== 0;
            }
            return res;
        }

        const sectSize = type === "segment" ? 32 + 9 * 4 : 32 + 8 * 4 + 2 * 8;
        const sections: any = [];
        for (let i = 0, off = total; i < nsects; i++, off += sectSize) {
            if (off + sectSize > buf.length) {
                throw new Error("Segment OOB");
            }
            const sectname = this.parseCStr(buf.subarray(off, off + 16));
            const segname = this.parseCStr(buf.subarray(off + 16, off + 32));

            if (type === "segment") {
                var addr = super.readUInt32(buf, off + 32);
                var size = super.readUInt32(buf, off + 36);
                var offset = super.readUInt32(buf, off + 40);
                var align = super.readUInt32(buf, off + 44);
                var reloff = super.readUInt32(buf, off + 48);
                var nreloc = super.readUInt32(buf, off + 52);
                var flags = super.readUInt32(buf, off + 56);
            } else {
                var addr = super.readUInt64(buf, off + 32);
                var size = super.readUInt64(buf, off + 40);
                var offset = super.readUInt32(buf, off + 48);
                var align = super.readUInt32(buf, off + 52);
                var reloff = super.readUInt32(buf, off + 56);
                var nreloc = super.readUInt32(buf, off + 60);
                var flags = super.readUInt32(buf, off + 64);
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
                data: file.subarray(offset, offset + size)
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
    }

    parseLinkEdit(type: any, buf: Buffer): LinkEdit {
        if (buf.length !== 8) {
            throw new Error("link_edit OOB");
        }

        return {
            type: type,
            dataoff: super.readUInt32(buf, 0),
            datasize: super.readUInt32(buf, 4)
        };
    }

    parseCStr(buf: Buffer): string {
        for (var i = 0; i < buf.length; i++) {
            if (buf[i] === 0) {
                break;
            }
        }
        return buf.subarray(0, i).toString();
    }

    parseCommand(type: string, buf: Buffer, file: any): LoadCommand {
        switch (type) {
            case 'segment':
                return this.parseSegmentCmd(type, buf, file);
            case 'segment_64':
                return this.parseSegmentCmd(type, buf, file);
            case "symtab":
                return this.parseSymtab(type, buf);
            case "dyld_exports_trie":
                return this.parseLinkEdit(type, buf);
            case "dyld_chained_fixups":
                return this.parseLinkEdit(type, buf);
            case "main":
                return this.parseMain(type, buf);
            case "symseg":
                return this.parseSymseg(type, buf);
            case "encryption_info":
                return this.parseEncryptionInfo(type, buf);
            case "encryption_info_64":
                return this.parseEncryptionInfo64(type, buf);
            case "rpath":
                return this.parseRpath(type, buf);
            case "dysymtab":
                return this.parseDysymtab(type, buf);
            case "id_dylib":
            case "load_dylib":
            case "load_weak_dylib":
                return this.parseLoadDylib(type, buf);
            case "id_dylinker":
            case "load_dylinker":
                return this.parseLoadDylinker(type, buf);
            case "version_min_macosx":
            case "version_min_iphoneos":
                return this.parseVersionMin(type, buf);
            case "code_signature":
            case "segment_split_info":
            case "data_in_code":
            case "dylib_code_sign_drs":
                return this.parseLinkEdit(type, buf);
            case "function_starts":
                return this.parseFunctionStarts(type, buf, file);
        }
        return { type: type, data: buf } as UnknownLoadCommand;
    }

    parseSymtab(type: any, buf: Buffer): Symtab {
        if (buf.length !== 16) {
            throw new Error('symtab OOB');
        }
        return {
            type: type,
            symoff: super.readUInt32(buf, 0),
            nsyms: super.readUInt32(buf, 4),
            stroff: super.readUInt32(buf, 8),
            strsize: super.readUInt32(buf, 12)
        };
    }

    parseSymseg(type: any, buf: any): Symseg {
        if (buf.length !== 8) {
            throw new Error('symseg OOB');
        }
        return {
            type: type,
            offset: super.readUInt32(buf, 0),
            size: super.readUInt32(buf, 4)
        };
    }

    parseEncryptionInfo(type: any, buf: any): EncryptionInfo {
        if (buf.length !== 12) {
            throw new Error('encryptinfo OOB');
        }
        return {
            type: type,
            offset: super.readUInt32(buf, 0),
            size: super.readUInt32(buf, 4),
            id: super.readUInt32(buf, 8),
        };
    }

    parseEncryptionInfo64(type: any, buf: any): EncryptionInfo {
        if (buf.length !== 16) {
            throw new Error('encryptinfo64 OOB');
        }
        return this.parseEncryptionInfo(type, buf.subarray(0, 12));
    }

    parseDysymtab(type: any, buf: any): Dysymtab {
        if (buf.length !== 72) {
            throw new Error('dysymtab OOB');
        }

        return {
            type: type,
            ilocalsym: super.readUInt32(buf, 0),
            nlocalsym: super.readUInt32(buf, 4),
            iextdefsym: super.readUInt32(buf, 8),
            nextdefsym: super.readUInt32(buf, 12),
            iundefsym: super.readUInt32(buf, 16),
            nundefsym: super.readUInt32(buf, 20),
            tocoff: super.readUInt32(buf, 24),
            ntoc: super.readUInt32(buf, 28),
            modtaboff: super.readUInt32(buf, 32),
            nmodtab: super.readUInt32(buf, 36),
            extrefsymoff: super.readUInt32(buf, 40),
            nextrefsyms: super.readUInt32(buf, 44),
            indirectsymoff: super.readUInt32(buf, 48),
            nindirectsyms: super.readUInt32(buf, 52),
            extreloff: super.readUInt32(buf, 56),
            nextrel: super.readUInt32(buf, 60),
            locreloff: super.readUInt32(buf, 64),
            nlocrel: super.readUInt32(buf, 68)
        };
    }

    parseLoadDylinker(type: any, buf: any): Dylinker {
        return {
            type: type,
            cmd: this.parseLCStr(buf, 0)
        };
    }

    parseRpath(type: any, buf: any): Rpath {
        if (buf.length < 8)
            throw new Error("lc_rpath OOB");

        return {
            type: type,
            name: this.parseLCStr(buf, 0),
        };
    }

    parseLoadDylib(type: any, buf: any): LoadDylib {
        if (buf.length < 16) {
            throw new Error("load_dylib OOB");
        }
        return {
            type: type,
            name: this.parseLCStr(buf, 0),
            timestamp: super.readUInt32(buf, 4),
            current_version: super.readUInt32(buf, 8),
            compatibility_version: super.readUInt32(buf, 12)
        };
    }

    parseVersionMin(type: any, buf: any): VersionMin {
        if (buf.length !== 8) {
            throw new Error("min version OOB");
        }
        return {
            type: type,
            version: super.readUInt16(buf, 2) + '.' + buf[1] + '.' + buf[0],
            sdk: super.readUInt16(buf, 6) + '.' + buf[5] + '.' + buf[4]
        };
    }
}

export interface LoadDylib {
    type: any,
    name: string,
    timestamp: number,
    current_version: number,
    compatibility_version: number
}

export interface Dylinker {
    type: any,
    cmd: string
}

export interface VersionMin {
    type: any,
    version: string,
    sdk: string
}

export interface Rpath {
    type: any,
    name: string
}

export interface Symtab {
    type: string,
    symoff: number,
    nsyms: number,
    stroff: number,
    strsize: number,
}

export interface FunctionStart {
    type: string,
    dataoff: any,
    datasize: any,
    addresses: any
}

export interface Symseg {
    type: string,
    offset: number,
    size: number
}

export interface LinkEdit {
    type: string,
    dataoff: number,
    datasize: number
}

export interface EncryptionInfo {
    type: string,
    offset: number,
    size: number,
    id: number
}

export interface SectionAttribute {
    usr: any,
    sys: any
}

export interface Section {
    sectname: string,
    segname: string,
    addr: number,
    size: number,
    offset: number,
    align: number,
    reloff: number,
    nreloc: number,
    type: string,
    attributes: SectionAttribute,
    data: Buffer
}

export interface SegmentCmd {
    type: string,
    name: string,
    vmaddr: number,
    vmsize: number,
    fileoff: number,
    filesize: number,
    maxprot: Protection,
    initprot: Protection,
    nsects: number,
    flags: any, ///this.mapFlags(flags, constants.segFlag),
    sections: Section[]
}

export interface Protection {
    read: boolean,
    write: boolean,
    exec: boolean,
}

export interface CpuInfo {
    type: string,
    subtype: number,
    endian: string
}

export interface Header {
    bits: number,
    magic: number,
    cpu: CpuInfo,
    filetype: string,
    ncmds: number,
    sizeofcmds: number,
    flags: any,
    cmds: any,
    hsize: number,
    body?: Buffer
}

export interface Dysymtab {
    type: string,
    ilocalsym: number,
    nlocalsym: number,
    iextdefsym: number,
    nextdefsym: number,
    iundefsym: number,
    nundefsym: number,
    tocoff: number,
    ntoc: number,
    modtaboff: number,
    nmodtab: number,
    extrefsymoff: number,
    nextrefsyms: number,
    indirectsymoff: number,
    nindirectsyms: number,
    extreloff: number,
    nextrel: number,
    locreloff: number,
    nlocrel: number
};

export interface UnknownLoadCommand {
    type: string,
    data: Buffer
}

export interface Main {
    type: string,
    entryoff: number,
    stacksize: number,
};

type LoadCommand = SegmentCmd | Symseg | Main | LinkEdit | Symtab | Rpath | Dylinker | Dysymtab | LoadDylib | VersionMin | UnknownLoadCommand;

//NOTE: returned addresses are relative to the "base address", i.e.
//       the vmaddress of the first "non-null" segment [e.g. initproto!=0]
//       (i.e. __TEXT ?)
function subtypeFromCpu(endian: string, cputype: string, cpusubtype: number) {
    if (endian === 'multiple') {
        return "all";
    }
    if (cpusubtype === 0) {
        return 'none';
    }
    return constants.cpuSubType[cputype][cpusubtype];
}

function endianFromCpu(cpusubtype: number): string {
    if ((cpusubtype & constants.endian.multiple) === constants.endian.multiple) {
        return "multiple";
    }
    if (cpusubtype & constants.endian.be) {
        return "be";
    }
    return "le";
}
