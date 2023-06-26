import { constants } from "./macho/constants.js"
import { Parser } from "./macho/parser.js"

export default {
    constants: constants,
    Parser: Parser,
    parse: function parse(buf: Buffer) {
        return new Parser().execute(buf);
    }
};
