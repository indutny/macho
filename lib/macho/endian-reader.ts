export class Reader {
    endian: string | null;
    word: number;
    constructor(endian: (string| null) = null, word: number = 4) {
        this.endian = null;
        this.word = 4;
        if (endian) {
            this.setEndian(endian);
        }
        if (word) {
            this.setWord(word);
        }
    }

    setEndian(endian: string) {
        this.endian = /le|lsb|little/i.test(endian) ? "le" : "be";
    }

    setWord(word: number) {
        this.word = word;
    }

    readUInt8(buf: any, offset: any): number {
        return buf.readUInt8(offset);
    }

    readInt8(buf: any, offset: any): number {
        return buf.readInt8(offset);
    }

    readUInt16(buf: any, offset: any): number {
        if (this.endian === 'le') {
            return buf.readUInt16LE(offset);
        }
        return buf.readUInt16BE(offset);
    }

    readInt16(buf: any, offset: any): number {
        if (this.endian === 'le') {
            return buf.readInt16LE(offset);
        }
        return buf.readInt16BE(offset);
    }

    readUInt32(buf: any, offset: number): number {
        if (this.endian === 'le') {
            return buf.readUInt32LE(offset);
        }
        return buf.readUInt32BE(offset);
    }

    readInt32(buf: any, offset: number): number {
        if (this.endian === 'le') {
            return buf.readInt32LE(offset);
        }
        return buf.readInt32BE(offset);
    }

    readUInt64(buf: any, offset: number): number {
        const a = this.readUInt32(buf, offset);
        const b = this.readUInt32(buf, offset + 4);
        if (this.endian === 'le') {
            return a + b * 0x100000000;
        }
        return b + a * 0x100000000;
    }

    readInt64(buf: any, offset: number): number {
        if (this.endian === 'le') {
            const a = this.readUInt32(buf, offset);
            const b = this.readInt32(buf, offset + 4);
            return a + b * 0x100000000;
        }
        const a = this.readInt32(buf, offset);
        const b = this.readUInt32(buf, offset + 4);
        return b + a * 0x100000000;
    }

    readHalf(buf: any, offset: number): number {
        if (this.word === 2) {
            return this.readInt8(buf, offset);
        }
        if (this.word === 4) {
            return this.readInt16(buf, offset);
        }
        return this.readInt32(buf, offset);
    }

    readUHalf(buf: any, offset: number): number {
        if (this.word === 2) {
            return this.readUInt8(buf, offset);
        }
        if (this.word === 4) {
            return this.readUInt16(buf, offset);
        }
        return this.readUInt32(buf, offset);
    }

    readWord(buf: any, offset: number) {
        switch (this.word) {
            case 1:
                return this.readInt8(buf, offset);
            case 2:
                return this.readInt16(buf, offset);
            case 4:
                return this.readInt32(buf, offset);
            default:
                return this.readInt64(buf, offset);
        }
    }

    readUWord(buf: any, offset: any): number {
        switch (this.word) {
            case 1:
                return this.readUInt8(buf, offset);
            case 2:
                return this.readUInt16(buf, offset);
            case 4:
                return this.readUInt32(buf, offset);
            default:
                return this.readUInt64(buf, offset);
        }
    }
}