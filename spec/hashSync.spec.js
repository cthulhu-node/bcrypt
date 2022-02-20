const { describe, it } = require('mocha');
const assert = require('assert');
const hashSync = require('../lib/bcrypt').hashSync;

describe('hashSync', () => {
    it('hashSync', () => {
        const hashed = hashSync('test', '$2a$12$0kdgu4H1rjsNkd67g/YfvOdwCBlv2');
        assert.ok(hashed);
        assert.ok(typeof hashed === 'string');
        assert.ok(hashed.length !== 0);
        assert.ok(hashed.length === 60);
        assert.ok(hashed === '$2a$12$0kdgu4H1rjsNkd67g/YfvOdwCBlv2.DLR7G3jyANY2Lo3Lm62N6o6');
    });
});
