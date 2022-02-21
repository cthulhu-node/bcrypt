const { describe, it } = require('mocha');
const assert = require('assert');
const bcrypt = require('../lib/bcrypt');

describe('genSaltSync', () => {
    it('genSaltSync', () => {
        const salt = bcrypt.genSaltSync(10);
        assert.ok(salt);
        assert.ok(typeof salt == 'string');
        assert.ok(salt.length !== 0);
        assert.ok(salt.length === 29);
    });

    it('genSaltSync Error handling', () => {
        assert.throws(() => { bcrypt.genSaltSync(1.9)}, /Illegal arguments/);
        assert.throws(() => { bcrypt.genSaltSync('2')}, /Illegal arguments/);
    });
});