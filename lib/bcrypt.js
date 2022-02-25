const crypto = require('crypto');
const base64Utils = require('./bcrypt/util/base64.js');
const impl = require('./bcrypt/impl.js');
const constants = require('./bcrypt/constants.js');
const BCRYPT_SALT_LEN = constants.BCRYPT_SALT_LEN;
const GENSALT_DEFAULT_LOG2_ROUNDS = constants.GENSALT_DEFAULT_LOG2_ROUNDS;

function Bcrypt() {}

/**
 * Synchronously generates a salt.
 * @param {number=} rounds Number of rounds to use, defaults to 10 if omitted
 * @returns {string} Resulting salt
 * @throws {TypeError} If rounds is not a valid integer
 */
Bcrypt.prototype.genSaltSync = function(rounds) {
    !rounds && (rounds = GENSALT_DEFAULT_LOG2_ROUNDS);
    if (typeof rounds !== 'number' || !Number.isInteger(rounds)) {
        throw TypeError("Illegal arguments: "+(typeof rounds)+", "+(typeof seed_length));
    }
    !rounds && (rounds = GENSALT_DEFAULT_LOG2_ROUNDS);
    (rounds < 4) && (rounds = 4), (rounds > 31) && (rounds = 31);

    return '$2a$' + ((rounds < 10) && '0' || '') + rounds + '$' + base64Utils.encode(crypto.randomBytes(BCRYPT_SALT_LEN), BCRYPT_SALT_LEN);
};

/**
 * Asynchronously generates a salt.
 * @param {(number} rounds Number of rounds to use, defaults to 10 if omitted
 * @returns {Promise}
 * @throws {TypeError} If rounds is not a valid integer
 */
Bcrypt.prototype.genSalt = async function(rounds) {
    return this.genSaltSync(rounds);
};

/**
 * Synchronously generates a hash for the given string.
 * @param {string} value String to hash
 * @param {(number|string)=} salt Salt length to generate or salt to use, default to 10
 * @returns {string} Resulting hash
 */
Bcrypt.prototype.hashSync = function(value, salt) {
    (typeof salt === 'undefined') && (salt = GENSALT_DEFAULT_LOG2_ROUNDS);
    (typeof salt === 'number') && (salt = this.genSaltSync(salt));
    if (typeof value !== 'string' || typeof salt !== 'string') {
        throw TypeError("Illegal arguments: "+(typeof value)+', '+(typeof salt));
    }
    return impl.hash(value, salt);
};

/**
 * Asynchronously generates a hash for the given string.
 * @param {string} s String to hash
 * @param {number|string} salt Salt length to generate or salt to use
 * @returns {Promise}
 */
Bcrypt.prototype.hash = async function(s, salt) {
    return this.hashSync(s, salt);
}
/**
 * Synchronously tests a string against a hash.
 * @param {string} s String to compare
 * @param {string} hash Hash to test against
 * @returns {boolean} true if matching, otherwise false
 * @throws {Error} If an argument is illegal
 */
Bcrypt.prototype.compareSync = function(s, hash) {
    if (typeof s !== "string" || typeof hash !== "string")
        throw TypeError("Illegal arguments: "+(typeof s)+', '+(typeof hash));
    if (hash.length !== 60)
        return false;
    return crypto.timingSafeEqual(Buffer.from(this.hashSync(s, hash.substring(0, hash.length-31))), Buffer.from(hash));
};

/**
 * Asynchronously compares the given data against the given hash.
 * @param {string} s Data to compare
 * @param {string} hash Data to be compared to
 * @returns {Promise}
 */
Bcrypt.prototype.compare = async function(s, hash) {
    return this.compareSync(s, hash);
};

/**
 * Gets the number of rounds used to encrypt the specified hash.
 * @param {string} hash Hash to extract the used number of rounds from
 * @returns {number} Number of rounds used
 * @throws {Error} If `hash` is not a string
 */
Bcrypt.prototype.getRounds = function(hash) {
    if (typeof hash !== "string") {
        throw TypeError("Illegal arguments: " + (typeof hash));
    }
    return ~~(hash[4] + hash[5]);
};

/**
 * Gets the salt portion from a hash. Does not validate the hash.
 * @param {string} hash Hash to extract the salt from
 * @returns {string} Extracted salt part
 * @throws {Error} If `hash` is not a string or otherwise invalid
 */
Bcrypt.prototype.getSalt = function(hash) {
    if (typeof hash !== 'string') {
        throw TypeError("Illegal arguments: "+(typeof hash));
    }
    if (hash.length !== 60) {
        throw TypeError("Illegal hash length: "+hash.length+" != 60");
    }
    return hash.substring(0, 29);
};

module.exports = new Bcrypt();
