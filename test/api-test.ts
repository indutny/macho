import macho from "../lib/macho.js";
import fs from "fs";
import assert from "assert";

describe('macho', function() {
  it("should parse node.js binary", function() {
    const exe = macho.parse(fs.readFileSync("./test/bins/ls"));
    assert(exe.bits === 64 || exe.bits === 32);
    assert.equal(exe.filetype, 'execute');
    assert(exe.cmds.some(function(cmd:any) {
      return cmd.type === "dysymtab" && cmd.nindirectsyms === 174;
    }));
    assert(exe.cmds.some(function(cmd:any) {
      return cmd.type === "function_starts" &&
             cmd.addresses.length;
    }));
  });
});
