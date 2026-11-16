import test from 'node:test';
import assert from 'node:assert/strict';
import { TRANSLATIONS, isRtlLanguage, translate, type TranslationKey } from './translations';

test('en, ckb, and ar translation dictionaries contain identical non-empty key sets', () => {
  const enKeys = Object.keys(TRANSLATIONS.en).sort() as TranslationKey[];
  const ckbKeys = Object.keys(TRANSLATIONS.ckb).sort() as TranslationKey[];
  const arKeys = Object.keys(TRANSLATIONS.ar).sort() as TranslationKey[];

  assert.deepEqual(ckbKeys, enKeys);
  assert.deepEqual(arKeys, enKeys);

  for (const key of enKeys) {
    assert.ok(TRANSLATIONS.en[key].trim().length > 0, `Missing en value for ${key}`);
    assert.ok(TRANSLATIONS.ckb[key].trim().length > 0, `Missing ckb value for ${key}`);
    assert.ok(TRANSLATIONS.ar[key].trim().length > 0, `Missing ar value for ${key}`);
  }
});

test('Sorani Kurdish (ckb) and Arabic (ar) use authentic native scripts and RTL direction', () => {
  assert.equal(isRtlLanguage('en'), false);
  assert.equal(isRtlLanguage('ckb'), true);
  assert.equal(isRtlLanguage('ar'), true);

  assert.match(TRANSLATIONS.ckb.overviewTitle, /[ڕڵێۆەڤگپچژک]/);
  assert.match(TRANSLATIONS.ar.overviewTitle, /[\u0600-\u06FF]/);
  assert.notEqual(TRANSLATIONS.ckb.overviewTitle, TRANSLATIONS.ar.overviewTitle);
});

test('translate interpolates placeholders cleanly across all languages', () => {
  for (const lang of ['en', 'ckb', 'ar'] as const) {
    const pagination = translate(lang, 'trafficPagination', { total: 6234, page: 2, totalPages: 250 });
    assert.ok(pagination.includes('6234'));
    assert.ok(pagination.includes('2'));
    assert.ok(pagination.includes('250'));
    assert.equal(pagination.includes('{'), false);

    const quota = translate(lang, 'geoQuotaLine', { remaining: 28, limit: 30 });
    assert.ok(quota.includes('28'));
    assert.ok(quota.includes('30'));
    assert.equal(quota.includes('{'), false);
  }
});
