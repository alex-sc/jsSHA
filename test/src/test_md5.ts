import { describe, it } from "mocha";
import { assert } from "chai";
import jsSHA from "../../src/sha";

const L = 128;

describe("MD5 tests", () => {
  it("Empty hash", () => {
    const hashObj = new jsSHA("MD5", "TEXT");
    hashObj.update("");
    const hexHash = hashObj.getHash("HEX", {
      outputLen: L,
    });
    assert.equal(hexHash, "d41d8cd98f00b204e9800998ecf8427e");
  });

  it("a", () => {
    const hashObj = new jsSHA("MD5", "TEXT");
    hashObj.update("a");
    const hexHash = hashObj.getHash("HEX", {
      outputLen: L,
    });
    assert.equal(hexHash, "0cc175b9c0f1b6a831c399e269772661");
  });

  it("ab", () => {
    const hashObj = new jsSHA("MD5", "TEXT");
    hashObj.update("ab");
    const hexHash = hashObj.getHash("HEX", {
      outputLen: L,
    });
    assert.equal(hexHash, "187ef4436122d1cc2f40dc2b92f0eba0");
  });

  it("abc", () => {
    const hashObj = new jsSHA("MD5", "TEXT");
    hashObj.update("abc");
    const hexHash = hashObj.getHash("HEX", {
      outputLen: L,
    });
    assert.equal(hexHash, "900150983cd24fb0d6963f7d28e17f72");
  });

  it("abcd", () => {
    const hashObj = new jsSHA("MD5", "TEXT");
    hashObj.update("abcd");
    const hexHash = hashObj.getHash("HEX", {
      outputLen: L,
    });
    assert.equal(hexHash, "e2fc714c4727ee9395f324cd2e7f331f");
  });

  it("The quick brown", () => {
    const hashObj = new jsSHA("MD5", "TEXT");
    hashObj.update("The quick brown fox jumps over the lazy dog");
    const hexHash = hashObj.getHash("HEX", {
      outputLen: L,
    });
    assert.equal(hexHash, "9e107d9d372bb6826bd81d3542a419d6");
  });

  it("The quick brown.", () => {
    const hashObj = new jsSHA("MD5", "TEXT");
    hashObj.update("The quick brown fox jumps over the lazy dog.");
    const hexHash = hashObj.getHash("HEX", {
      outputLen: L,
    });
    assert.equal(hexHash, "e4d909c290d0fb1ca068ffaddf22cbd0");
  });

  it("Long", () => {
    const hashObj = new jsSHA("MD5", "TEXT");
    hashObj.update(
      "The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.",
    );
    const hexHash = hashObj.getHash("HEX", {
      outputLen: L,
    });
    assert.equal(hexHash, "ad3e53b540ad33873de4989099768508");
  });
});
