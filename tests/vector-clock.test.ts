import { describe, it, expect } from 'vitest';
import {
  incrementClock,
  mergeClocks,
  compareClocks,
  dominates,
  createEmptyMetadata,
} from '../src/sync/sync-engine';

describe('vector clock operations', () => {
  it('incrementClock adds device with counter 1', () => {
    const c = incrementClock({}, 'dev-a');
    expect(c).toEqual({ 'dev-a': 1 });
  });

  it('incrementClock preserves other devices and bumps own counter', () => {
    const base = { 'dev-a': 3, 'dev-b': 1 };
    const c = incrementClock(base, 'dev-a');
    expect(c).toEqual({ 'dev-a': 4, 'dev-b': 1 });
  });

  it('incrementClock is immutable', () => {
    const base = { 'dev-a': 1 };
    const c = incrementClock(base, 'dev-a');
    expect(base).toEqual({ 'dev-a': 1 });
    expect(c).not.toBe(base);
  });

  it('mergeClocks takes max of each entry', () => {
    const a = { 'dev-a': 2, 'dev-b': 1 };
    const b = { 'dev-a': 1, 'dev-b': 3, 'dev-c': 1 };
    expect(mergeClocks(a, b)).toEqual({ 'dev-a': 2, 'dev-b': 3, 'dev-c': 1 });
  });

  it('compareClocks returns equal for identical clocks', () => {
    expect(compareClocks({ a: 1 }, { a: 1 })).toBe('equal');
    expect(compareClocks({}, {})).toBe('equal');
  });

  it('compareClocks returns before/after correctly', () => {
    expect(compareClocks({ a: 1 }, { a: 2 })).toBe('before');
    expect(compareClocks({ a: 2 }, { a: 1 })).toBe('after');
    expect(compareClocks({ a: 1, b: 1 }, { a: 2, b: 1 })).toBe('before');
  });

  it('compareClocks returns concurrent when neither dominates', () => {
    expect(compareClocks({ a: 2, b: 1 }, { a: 1, b: 2 })).toBe('concurrent');
    expect(compareClocks({ a: 2 }, { a: 1, b: 1 })).toBe('concurrent');
  });

  it('dominates is true for after and equal', () => {
    expect(dominates({ a: 2 }, { a: 1 })).toBe(true);
    expect(dominates({ a: 1 }, { a: 1 })).toBe(true);
    expect(dominates({ a: 1 }, { a: 2 })).toBe(false);
    expect(dominates({ a: 2, b: 1 }, { a: 1, b: 2 })).toBe(false);
  });

  it('createEmptyMetadata has version 2 and empty maps', () => {
    const m = createEmptyMetadata('vault-1', 1024);
    expect(m.version).toBe(2);
    expect(m.vaultId).toBe('vault-1');
    expect(m.chunkSize).toBe(1024);
    expect(m.files).toEqual({});
    expect(m.deleted).toEqual({});
    expect(m.vectorClock).toEqual({});
    expect(m.sequence).toBe(0);
    expect(m.updatedAt).toBeDefined();
  });
});