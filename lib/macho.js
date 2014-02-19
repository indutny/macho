var macho = exports;

macho.constants = require('./macho/constants');
macho.Parser = require('./macho/parser');

macho.parse = function parse(buf) {
  return new macho.Parser().execute(buf);
};
