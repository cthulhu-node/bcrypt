const base64Utils = require('./util/base64.js');
const constants = require('./constants.js');
const P_ORIG = constants.P_ORIG;
const S_ORIG = constants.S_ORIG;
const C_ORIG = constants.C_ORIG;

function Impl() { }

/**
 * @param {Array.<number>} lr
 * @param {number} off
 * @param {Array.<number>} P
 * @param {Array.<number>} S
 * @returns {Array.<number>}
 * @inner
 */
function _encipher(lr, offset, P, S) {
    let l = lr[offset] ^ P[0];
    let r = lr[offset + 1] ^ P[1] ^ ((S[l >>> 24] + S[0x100 | ((l >> 16) & 0xff)] ^ S[0x200 | ((l >> 8) & 0xff)]) + S[0x300 | (l & 0xff)]);
    l = l ^ P[2] ^ ((S[r >>> 24] + S[0x100 | ((r >> 16) & 0xff)] ^ S[0x200 | ((r >> 8) & 0xff)]) + S[0x300 | (r & 0xff)]);
    r = r ^ P[3] ^ ((S[l >>> 24] + S[0x100 | ((l >> 16) & 0xff)] ^ S[0x200 | ((l >> 8) & 0xff)]) + S[0x300 | (l & 0xff)]);
    l = l ^ P[4] ^ ((S[r >>> 24] + S[0x100 | ((r >> 16) & 0xff)] ^ S[0x200 | ((r >> 8) & 0xff)]) + S[0x300 | (r & 0xff)]);
    r = r ^ P[5] ^ ((S[l >>> 24] + S[0x100 | ((l >> 16) & 0xff)] ^ S[0x200 | ((l >> 8) & 0xff)]) + S[0x300 | (l & 0xff)]);
    l = l ^ P[6] ^ ((S[r >>> 24] + S[0x100 | ((r >> 16) & 0xff)] ^ S[0x200 | ((r >> 8) & 0xff)]) + S[0x300 | (r & 0xff)]);
    r = r ^ P[7] ^ ((S[l >>> 24] + S[0x100 | ((l >> 16) & 0xff)] ^ S[0x200 | ((l >> 8) & 0xff)]) + S[0x300 | (l & 0xff)]);
    l = l ^ P[8] ^ ((S[r >>> 24] + S[0x100 | ((r >> 16) & 0xff)] ^ S[0x200 | ((r >> 8) & 0xff)]) + S[0x300 | (r & 0xff)]);
    r = r ^ P[9] ^ ((S[l >>> 24] + S[0x100 | ((l >> 16) & 0xff)] ^ S[0x200 | ((l >> 8) & 0xff)]) + S[0x300 | (l & 0xff)]);
    l = l ^ P[10] ^ ((S[r >>> 24] + S[0x100 | ((r >> 16) & 0xff)] ^ S[0x200 | ((r >> 8) & 0xff)]) + S[0x300 | (r & 0xff)]);
    r = r ^ P[11] ^ ((S[l >>> 24] + S[0x100 | ((l >> 16) & 0xff)] ^ S[0x200 | ((l >> 8) & 0xff)]) + S[0x300 | (l & 0xff)]);
    l = l ^ P[12] ^ ((S[r >>> 24] + S[0x100 | ((r >> 16) & 0xff)] ^ S[0x200 | ((r >> 8) & 0xff)]) + S[0x300 | (r & 0xff)]);
    r = r ^ P[13] ^ ((S[l >>> 24] + S[0x100 | ((l >> 16) & 0xff)] ^ S[0x200 | ((l >> 8) & 0xff)]) + S[0x300 | (l & 0xff)]);
    l = l ^ P[14] ^ ((S[r >>> 24] + S[0x100 | ((r >> 16) & 0xff)] ^ S[0x200 | ((r >> 8) & 0xff)]) + S[0x300 | (r & 0xff)]);
    r = r ^ P[15] ^ ((S[l >>> 24] + S[0x100 | ((l >> 16) & 0xff)] ^ S[0x200 | ((l >> 8) & 0xff)]) + S[0x300 | (l & 0xff)]);
    lr[offset + 1] = l ^ P[16] ^ ((S[r >>> 24] + S[0x100 | ((r >> 16) & 0xff)] ^ S[0x200 | ((r >> 8) & 0xff)]) + S[0x300 | (r & 0xff)]);
    lr[offset] = r ^ P[17];
}

/**
 * @param {Array.<number>} data
 * @param {number} offp
 * @returns {{key: number, offp: number}}
 * @inner
 */
function _streamtoword(data, offset, result) {
    const dataLength = data.length;
    let key = 0;
    key = (key << 8) | (data[offset] & 0xff);
    offset = (offset + 1) % dataLength;
    key = (key << 8) | (data[offset] & 0xff);
    offset = (offset + 1) % dataLength;
    key = (key << 8) | (data[offset] & 0xff);
    offset = (offset + 1) % dataLength;
    result.key = (key << 8) | (data[offset] & 0xff);
    result.offset = (offset + 1) % dataLength;
}

/**
 * @param {Array.<number>} key
 * @param {Array.<number>} P
 * @param {Array.<number>} S
 * @inner
 */
function _key(key, P, S) {
    let lr = [0, 0],
        sw = { key: 0, offset: 0 },
        i = 0;

    for (i = 0; i < 18; i++) {
        _streamtoword(key, sw.offset, sw),
            P[i] ^= sw.key;
    }
    for (i = 0; i < 18; i++) {
        _encipher(lr, 0, P, S), P[i++] = lr[0], P[i] = lr[1];
    }
    for (i = 0; i < 1024; i++) {
        _encipher(lr, 0, P, S), S[i++] = lr[0], S[i] = lr[1];
    }
}

/**
 * Expensive key schedule Blowfish.
 * @param {Array.<number>} data
 * @param {Array.<number>} key
 * @param {Array.<number>} P
 * @param {Array.<number>} S
 * @inner
 */
function _ekskey(data, key, P, S) {
    let lr = [0, 0],
        sw = { key: 0, offset: 0 },
        i = 0;
    for (i = 0; i < 18; i++) {
        _streamtoword(key, sw.offset, sw),
            P[i] = P[i] ^ sw.key;
    }
    sw.offset = 0;
    for (i = 0; i < 18; i++) {
        _streamtoword(data, sw.offset, sw),
            lr[0] = lr[0] ^ sw.key,
            _streamtoword(data, sw.offset, sw),
            lr[1] = lr[1] ^ sw.key,
            _encipher(lr, 0, P, S),
            P[i++] = lr[0],
            P[i] = lr[1];
    }
    for (i = 0; i < 1024; i++) {
        _streamtoword(data, sw.offset, sw),
            lr[0] = lr[0] ^ sw.key,
            _streamtoword(data, sw.offset, sw),
            lr[1] = lr[1] ^ sw.key,
            _encipher(lr, 0, P, S),
            S[i++] = lr[0],
            S[i] = lr[1];
    }
}

/**
 * Internally crypts a string.
 * @param {Array.<number>} b Bytes to crypt
 * @param {Array.<number>} salt Salt bytes to use
 * @param {number} rounds Number of rounds
 *  omitted, the operation will be performed synchronously.
 * @returns {Array.<number>}
 * @inner
 */
function _crypt(b, salt, rounds) {
    const cdata = C_ORIG.slice();

    rounds = 1 << rounds;

    let i = 0;

    const P = new Int32Array(P_ORIG);
    const S = new Int32Array(S_ORIG);

    _ekskey(salt, b, P, S);

    for (i = 0; i < rounds; ++i) {
        _key(b, P, S);
        _key(salt, P, S);
    }
    for (i = 0; i < 64; ++i) {
        _encipher(cdata, 0, P, S), _encipher(cdata, 2, P, S), _encipher(cdata, 4, P, S);
    }
    const ret = [];
    for (i = 0; i < 6; ++i) {
        ret.push(~~((cdata[i] >> 24) & 0xff)), ret.push(~~((cdata[i] >> 16) & 0xff)), ret.push(~~((cdata[i] >> 8) & 0xff)), ret.push(~~(cdata[i] & 0xff));
    }
    return ret;
}

/**
 * Internally hashes a string.
 * @param {string} s String to hash
 * @param {?string} salt Salt to use, actually never null
 * @returns {string} Resulting hash
 * @inner
 */
Impl.prototype.hash = function (s, salt) {
    // Validate the salt
    var minor, offset;
    if (salt[0] !== '$' || salt[1] !== '2') {
        throw Error("Invalid salt version: " + salt.substring(0, 2));
    }
    if (salt[2] === '$') {
        minor = String.fromCharCode(0);
        offset = 3;
    } else {
        minor = salt[2];
        if ((minor !== 'a' && minor !== 'b' && minor !== 'y') || salt[3] !== '$') {
            throw Error("Invalid salt revision: " + salt.substring(2, 4));
        }
        offset = 4;
    }

    // Extract number of rounds
    if (salt[offset + 2] > '$') {
        throw Error("Missing salt rounds");
    }
    const rounds = ~~(salt[4] + salt[5]),
        real_salt = salt.substring(offset + 3, offset + 25);
    s += minor >= 'a' ? "\x00" : "";

    const passwordb = Buffer.from(s, 'binary'),
        saltb = base64Utils.decode(real_salt, 16);

    /**
     * Finishes hashing.
     * @param {Array.<number>} bytes Byte array
     * @returns {string}
     * @inner
     */
    function finish(bytes) {
        const res = [];
        res.push("$2");
        if (minor >= 'a')
            res.push(minor);
        res.push("$");
        if (rounds < 10)
            res.push("0");
        res.push(rounds.toString());
        res.push("$");
        res.push(base64Utils.encode(saltb, saltb.length));
        res.push(base64Utils.encode(bytes, C_ORIG.length * 4 - 1));
        return res.join('');
    }

    return finish(_crypt(passwordb, saltb, rounds));
}

module.exports = new Impl();
