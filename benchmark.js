"use strict";

const bcrypt = require('./lib/bcrypt');
const Benchmark = require('benchmark');

const suite = new Benchmark.Suite();

const testHash = '$2a$12$0kdgu4H1rjsNkd67g/YfvOdwCBlv2.DLR7G3jyANY2Lo3Lm62N6o6';

suite.add('genSaltSync', function() {
    const seed = bcrypt.genSaltSync(12);
});
suite.add('genSalt', {
    'defer': true,
    'fn': function (deferred) {
        // avoid test inlining
        suite.name;
        bcrypt.genSalt(12).then(() => deferred.resolve());
    }
});
suite.add('getRounds', function() {
    const rounds = bcrypt.getRounds(testHash);
});
suite.add('hashSync', function () {
    bcrypt.hashSync("Password", 10);
});
suite.add('hash', {
    'defer': true,
    'fn': function (deferred) {
        // avoid test inlining
        suite.name;
        bcrypt.hash("Password", 10).then(() => deferred.resolve());
    }
});
suite.on('cycle', function (event) { console.log(String(event.target)); })

suite.run({ async: true })
