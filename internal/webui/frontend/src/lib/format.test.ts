import { describe, expect, it } from 'vitest';
import { formatDuration, formatGoDuration, formatRemaining, parseDuration } from './format';

describe('parseDuration', () => {
  it.each([
    ['30m', 30 * 60_000],
    ['1h', 3_600_000],
    ['1h30m', 5_400_000],
    ['1.5h', 5_400_000],
    ['90s', 90_000],
    [' 2h ', 7_200_000],
  ])('parses %s', (input, expected) => {
    expect(parseDuration(input)).toBe(expected);
  });

  it.each(['', '30', 'soon', '-5m', '1d', '30 m', 'm30'])('rejects %j', (input) => {
    expect(parseDuration(input)).toBeNull();
  });
});

describe('formatting', () => {
  it('formats durations for people', () => {
    expect(formatDuration(30 * 60_000)).toBe('30 Min.');
    expect(formatDuration(3_600_000)).toBe('1 Std.');
    expect(formatDuration(5_400_000)).toBe('1 Std. 30 Min.');
    expect(formatGoDuration('2h')).toBe('2 Std.');
    expect(formatGoDuration('garbage')).toBe('garbage');
  });

  it('formats remaining time', () => {
    expect(formatRemaining(65_000)).toBe('01:05');
    expect(formatRemaining(3_725_000)).toBe('1:02:05');
    expect(formatRemaining(-1)).toBe('00:00');
  });
});
