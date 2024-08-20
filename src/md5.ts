import { jsSHABase, sha_variant_error } from "./common";
import { FormatNoTextType, packedValue } from "./custom_types";
import { getStrConverter } from "./converters";

// Base on https://github.com/blueimp/JavaScript-MD5/blob/master/js/md5.js
const A = 1732584193;
const B = -271733879;
const C = -1732584194;
const D = 271733878;

const blockSizeInBits = 512;

/**
 * Add integers, wrapping at 2^32.
 * This uses 16-bit operations internally to work around bugs in interpreters.
 *
 * @param {number} x First integer
 * @param {number} y Second integer
 * @returns {number} Sum
 */
function safeAdd(x: number, y: number): number {
  const lsw = (x & 0xffff) + (y & 0xffff);
  const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xffff);
}

/**
 * Bitwise rotate a 32-bit number to the left.
 *
 * @param {number} num 32-bit number
 * @param {number} cnt Rotation count
 * @returns {number} Rotated number
 */
function bitRotateLeft(num: number, cnt: number): number {
  return (num << cnt) | (num >>> (32 - cnt));
}

function md5cmn(q: number, a: number, b: number, x: number, s: number, t: number) {
  return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b);
}

function md5ff(a: number, b: number, c: number, d: number, x: number, s: number, t: number) {
  return md5cmn((b & c) | (~b & d), a, b, x, s, t);
}

function md5gg(a: number, b: number, c: number, d: number, x: number, s: number, t: number) {
  return md5cmn((b & d) | (c & ~d), a, b, x, s, t);
}

function md5hh(a: number, b: number, c: number, d: number, x: number, s: number, t: number) {
  return md5cmn(b ^ c ^ d, a, b, x, s, t);
}

function md5ii(a: number, b: number, c: number, d: number, x: number, s: number, t: number) {
  return md5cmn(c ^ (b | ~d), a, b, x, s, t);
}

function pad(wordArray: number[], bitLength: number): number[] {
  // Add the padding bit (0x80)
  const lBytePosition = bitLength % 4;
  const lWordCount = (bitLength - lBytePosition) / 4;

  wordArray[lWordCount] = wordArray[lWordCount] || 0;
  wordArray[lWordCount] |= 0x80 << (lBytePosition * 8);

  // Calculate the total length in 32-bit words after padding
  let lTotalWords = (((bitLength + 8) >>> 6) << 4) + 14;

  // Zero pad the array to make its length congruent to 448 mod 512 (56 mod 64 bytes)
  while (wordArray.length <= lTotalWords) {
    wordArray.push(0);
  }

  // Append the original length in bits at the end (64-bit integer, split into two 32-bit words)
  const originalLengthBits = bitLength * 8;
  wordArray[lTotalWords++] = originalLengthBits & 0xffffffff;
  wordArray[lTotalWords] = originalLengthBits >>> 32;

  return wordArray;
}

function roundMd5(x: number[], H: number[]) {
  if (x.length % 16 != 0) {
    throw new Error(x.length + "");
  }

  let a = H[0];
  let b = H[1];
  let c = H[2];
  let d = H[3];
  let olda;
  let oldb;
  let oldc;
  let oldd;

  for (let i = 0; i < x.length; i += 16) {
    olda = a;
    oldb = b;
    oldc = c;
    oldd = d;

    a = md5ff(a, b, c, d, x[i], 7, -680876936);
    d = md5ff(d, a, b, c, x[i + 1], 12, -389564586);
    c = md5ff(c, d, a, b, x[i + 2], 17, 606105819);
    b = md5ff(b, c, d, a, x[i + 3], 22, -1044525330);
    a = md5ff(a, b, c, d, x[i + 4], 7, -176418897);
    d = md5ff(d, a, b, c, x[i + 5], 12, 1200080426);
    c = md5ff(c, d, a, b, x[i + 6], 17, -1473231341);
    b = md5ff(b, c, d, a, x[i + 7], 22, -45705983);
    a = md5ff(a, b, c, d, x[i + 8], 7, 1770035416);
    d = md5ff(d, a, b, c, x[i + 9], 12, -1958414417);
    c = md5ff(c, d, a, b, x[i + 10], 17, -42063);
    b = md5ff(b, c, d, a, x[i + 11], 22, -1990404162);
    a = md5ff(a, b, c, d, x[i + 12], 7, 1804603682);
    d = md5ff(d, a, b, c, x[i + 13], 12, -40341101);
    c = md5ff(c, d, a, b, x[i + 14], 17, -1502002290);
    b = md5ff(b, c, d, a, x[i + 15], 22, 1236535329);

    a = md5gg(a, b, c, d, x[i + 1], 5, -165796510);
    d = md5gg(d, a, b, c, x[i + 6], 9, -1069501632);
    c = md5gg(c, d, a, b, x[i + 11], 14, 643717713);
    b = md5gg(b, c, d, a, x[i], 20, -373897302);
    a = md5gg(a, b, c, d, x[i + 5], 5, -701558691);
    d = md5gg(d, a, b, c, x[i + 10], 9, 38016083);
    c = md5gg(c, d, a, b, x[i + 15], 14, -660478335);
    b = md5gg(b, c, d, a, x[i + 4], 20, -405537848);
    a = md5gg(a, b, c, d, x[i + 9], 5, 568446438);
    d = md5gg(d, a, b, c, x[i + 14], 9, -1019803690);
    c = md5gg(c, d, a, b, x[i + 3], 14, -187363961);
    b = md5gg(b, c, d, a, x[i + 8], 20, 1163531501);
    a = md5gg(a, b, c, d, x[i + 13], 5, -1444681467);
    d = md5gg(d, a, b, c, x[i + 2], 9, -51403784);
    c = md5gg(c, d, a, b, x[i + 7], 14, 1735328473);
    b = md5gg(b, c, d, a, x[i + 12], 20, -1926607734);

    a = md5hh(a, b, c, d, x[i + 5], 4, -378558);
    d = md5hh(d, a, b, c, x[i + 8], 11, -2022574463);
    c = md5hh(c, d, a, b, x[i + 11], 16, 1839030562);
    b = md5hh(b, c, d, a, x[i + 14], 23, -35309556);
    a = md5hh(a, b, c, d, x[i + 1], 4, -1530992060);
    d = md5hh(d, a, b, c, x[i + 4], 11, 1272893353);
    c = md5hh(c, d, a, b, x[i + 7], 16, -155497632);
    b = md5hh(b, c, d, a, x[i + 10], 23, -1094730640);
    a = md5hh(a, b, c, d, x[i + 13], 4, 681279174);
    d = md5hh(d, a, b, c, x[i], 11, -358537222);
    c = md5hh(c, d, a, b, x[i + 3], 16, -722521979);
    b = md5hh(b, c, d, a, x[i + 6], 23, 76029189);
    a = md5hh(a, b, c, d, x[i + 9], 4, -640364487);
    d = md5hh(d, a, b, c, x[i + 12], 11, -421815835);
    c = md5hh(c, d, a, b, x[i + 15], 16, 530742520);
    b = md5hh(b, c, d, a, x[i + 2], 23, -995338651);

    a = md5ii(a, b, c, d, x[i], 6, -198630844);
    d = md5ii(d, a, b, c, x[i + 7], 10, 1126891415);
    c = md5ii(c, d, a, b, x[i + 14], 15, -1416354905);
    b = md5ii(b, c, d, a, x[i + 5], 21, -57434055);
    a = md5ii(a, b, c, d, x[i + 12], 6, 1700485571);
    d = md5ii(d, a, b, c, x[i + 3], 10, -1894986606);
    c = md5ii(c, d, a, b, x[i + 10], 15, -1051523);
    b = md5ii(b, c, d, a, x[i + 1], 21, -2054922799);
    a = md5ii(a, b, c, d, x[i + 8], 6, 1873313359);
    d = md5ii(d, a, b, c, x[i + 15], 10, -30611744);
    c = md5ii(c, d, a, b, x[i + 6], 15, -1560198380);
    b = md5ii(b, c, d, a, x[i + 13], 21, 1309151649);
    a = md5ii(a, b, c, d, x[i + 4], 6, -145523070);
    d = md5ii(d, a, b, c, x[i + 11], 10, -1120210379);
    c = md5ii(c, d, a, b, x[i + 2], 15, 718787259);
    b = md5ii(b, c, d, a, x[i + 9], 21, -343485551);

    a = safeAdd(a, olda);
    b = safeAdd(b, oldb);
    c = safeAdd(c, oldc);
    d = safeAdd(d, oldd);
  }

  return [a, b, c, d];
}

/**
 * Finalizes the SHA-1 hash.  This clobbers `remainder` and `H`.
 *
 * @param remainder Any leftover unprocessed packed ints that still need to be processed.
 * @param remainderBinLen The number of bits in `remainder`.
 * @param processedBinLen The number of bits already processed.
 * @param H The intermediate H values from a previous round.
 * @returns The array of integers representing the SHA-1 hash of message.
 */
function finalizeMD5(remainder: number[], remainderBinLen: number, processedBinLen: number, H: number[]): number[] {
  remainder.length = remainderBinLen / 32;
  const padded = pad(remainder, remainderBinLen + processedBinLen);

  return roundMd5(padded, H);
}

export default class jsMD5 extends jsSHABase<number[], "MD5"> {
  intermediateState: number[];
  variantBlockSize: number;
  bigEndianMod: -1 | 1;
  outputBinLen: number;
  isVariableLen: boolean;
  HMACSupported: boolean;

  /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
  converterFunc: (input: any, existingBin: number[], existingBinLen: number) => packedValue;
  roundFunc: (block: number[], H: number[]) => number[];
  finalizeFunc: (remainder: number[], remainderBinLen: number, processedBinLen: number, H: number[]) => number[];
  stateCloneFunc: (state: number[]) => number[];
  newStateFunc: (variant: "MD5") => number[];
  getMAC: () => number[];

  constructor(variant = "MD5", inputFormat: FormatNoTextType) {
    if ("MD5" !== variant) {
      throw new Error(sha_variant_error);
    }
    super(variant, inputFormat);

    this.HMACSupported = false;
    this.bigEndianMod = 1;
    this.variantBlockSize = blockSizeInBits;
    this.outputBinLen = 128;
    this.isVariableLen = false;
    this.intermediateState = [A, B, C, D];

    this.getMAC = function (): number[] {
      return [];
    };
    this.converterFunc = getStrConverter(this.inputFormat, this.utfType, this.bigEndianMod);
    this.roundFunc = function (block: number[], H: number[]): number[] {
      return roundMd5(block, H);
    };
    this.stateCloneFunc = function (state: number[]): number[] {
      return state.slice();
    };
    this.newStateFunc = function () {
      return [A, B, C, D];
    };
    this.finalizeFunc = finalizeMD5;
  }
}
