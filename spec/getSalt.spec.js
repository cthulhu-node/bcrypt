const { describe, it } = require('mocha');
const assert = require('assert');
const bcrypt = require('../lib/bcrypt');

describe('getSalt', () => {
    it('getSalt', () => {
        const salt = bcrypt.getSalt('$2a$12$0kdgu4H1rjsNkd67g/YfvOdwCBlv2.DLR7G3jyANY2Lo3Lm62N6o6');
        assert.ok(typeof salt === 'string');
        assert.ok(salt.length === 29);
        assert.ok(salt === '$2a$12$0kdgu4H1rjsNkd67g/YfvO');
    });
});