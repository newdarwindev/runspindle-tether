'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {zoomPreferences,validatePair,validateBitmap} = require('../tools/check_native_progress_zoom.cjs');
const normal = {cssZoom:'1',visualViewportScale:1,outerWidth:780,innerWidth:780,dpr:1};
const enlarged = {...normal,innerWidth:390,dpr:2};
test('native preference is partition dictionary, not CSS/device emulation',()=>{
  assert.equal(zoomPreferences(100).partition.default_zoom_level.x,0);
  assert.ok(Math.abs(zoomPreferences(200).partition.default_zoom_level.x-Math.log(2)/Math.log(1.2))<1e-12);
  assert.throws(()=>zoomPreferences(150));
});
test('actual native metrics qualify',()=>validatePair(normal,enlarged));
test('missing native zoom fails even when preference was requested',()=>assert.throws(()=>validatePair(normal,normal)));
test('CSS zoom is not native browser zoom',()=>assert.throws(()=>validatePair(normal,{...enlarged,cssZoom:'2'})));
test('visual viewport emulation is not native browser zoom',()=>assert.throws(()=>validatePair(normal,{...enlarged,visualViewportScale:2})));
test('device scale without native viewport change fails',()=>assert.throws(()=>validatePair(normal,{...enlarged,innerWidth:780})));
test('changing outer window instead of genuine zoom fails',()=>assert.throws(()=>validatePair(normal,{...enlarged,outerWidth:390})));

test('native bitmap dimensions and visible content qualify',()=>validateBitmap({size:[780,757],color_count_lower_bound:257},{width:780,height:757}));
test('CSS-sized clipped bitmap fails at native zoom',()=>assert.throws(()=>validateBitmap({size:[390,378],color_count_lower_bound:257},{width:780,height:757})));
test('missing lower half of full page fails',()=>assert.throws(()=>validateBitmap({size:[780,500],color_count_lower_bound:257},{width:780,height:1000})));
test('blank focused viewport fails despite valid dimensions',()=>assert.throws(()=>validateBitmap({size:[780,757],color_count_lower_bound:1},{width:780,height:757})));
