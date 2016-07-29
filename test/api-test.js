var macho = require('..');
var fs = require('fs');
var assert = require('assert');

describe('macho', function() {
  it('should parse node.js binary', function() {
    var exe = macho.parse(fs.readFileSync(process.execPath));
    assert(exe.bits === 64 || exe.bits === 32);
    assert.equal(exe.filetype, 'execute');
    assert(exe.cmds.some(function(cmd) {
      return cmd.type === 'version_min_macosx' &&
             cmd.version === '10.7.0';
    }));
    assert(exe.cmds.some(function(cmd) {
      return cmd.type === 'function_starts' &&
             cmd.addresses.length;
    }));
  });
});
