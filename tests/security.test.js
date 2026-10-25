const test = require('node:test');
const assert = require('node:assert/strict');
const {safeEqual, monthValid} = require('../src/security');
test('constant-time comparison helper accepts identical values',()=>{assert.equal(safeEqual('abc','abc'),true)});
test('constant-time comparison helper rejects different values and lengths',()=>{assert.equal(safeEqual('abc','abd'),false);assert.equal(safeEqual('abc','ab'),false)});
test('billing month validator accepts YYYY-MM only',()=>{assert.equal(monthValid('2026-10'),true);assert.equal(monthValid('2026-13'),false);assert.equal(monthValid('2026-1'),false);assert.equal(monthValid('2026-10-01'),false)});
