import { describe, it } from "mocha";
import { assert } from "chai";
import jsSHA from "../../src/sha";

const L = 128;

describe("Test Empty hash", () => {
  it("With No Inputs", () => {
    const hashObj = new jsSHA("MD5", "TEXT");
    hashObj.update("");
    const hexHash = hashObj.getHash("HEX", {
      outputLen: L,
    });
    assert.equal(hexHash, "d41d8cd98f00b204e9800998ecf8427e");
  });

  it("Test 1", () => {
    const hashObj = new jsSHA("MD5", "TEXT");
    hashObj.update("The quick brown fox jumps over the lazy dog");
    const hexHash = hashObj.getHash("HEX", {
      outputLen: L,
    });
    assert.equal(hexHash, "9e107d9d372bb6826bd81d3542a419d6");
  });

  it("Test 2", () => {
    const hashObj = new jsSHA("MD5", "TEXT");
    hashObj.update("The quick brown fox jumps over the lazy dog.");
    const hexHash = hashObj.getHash("HEX", {
      outputLen: L,
    });
    assert.equal(hexHash, "e4d909c290d0fb1ca068ffaddf22cbd0");
  });

  it("Test 3", () => {
    const hashObj = new jsSHA("MD5", "TEXT");
    hashObj.update(
      "The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.",
    );
    const hexHash = hashObj.getHash("HEX", {
      outputLen: L,
    });
    assert.equal(hexHash, "e4d909c290d0fb1ca068ffaddf22cbd0");
  });
});
