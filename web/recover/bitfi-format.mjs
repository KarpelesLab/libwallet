// The recovery page's pure logic, separate so it can be tested without a browser.

/** A base-unit amount as a decimal string, without trailing zeros. */
export function formatUnits(value, decimals) {
  const digits = BigInt(value).toString().padStart(decimals + 1, '0');
  const whole = digits.slice(0, digits.length - decimals);
  const fraction = decimals ? digits.slice(-decimals).replace(/0+$/, '') : '';
  return fraction ? `${whole}.${fraction}` : whole;
}

/** A decimal amount as a base-unit string. Throws a message fit to show. */
export function toBaseUnits(text, decimals) {
  const match = /^(\d*)(?:\.(\d*))?$/.exec(text.trim());
  if (!text.trim() || !match || (!match[1] && !match[2])) throw new Error('Enter an amount, like 0.5, or use Max.');
  const fraction = match[2] || '';
  if (fraction.length > decimals) throw new Error(`This asset has at most ${decimals} decimal places.`);
  const units = BigInt((match[1] || '0') + fraction.padEnd(decimals, '0'));
  if (units === 0n) throw new Error('Enter an amount above zero.');
  return units.toString();
}

/** What to say about a salt or secret while it's typed. Never changes the input. */
export function inputWarnings(label, value, min) {
  if (!value) return { level: '', text: '' };
  // eslint-disable-next-line no-control-regex
  if (/[^\x00-\x7f]/.test(value)) return { level: 'bad', text: `${label} has a character Bitfi devices can't use, such as a curly quote or accent.` };
  if (value !== value.trim()) return { level: 'warn', text: `${label} starts or ends with a space. Spaces count, so keep it only if you used it on your device.` };
  if (value.length < min) return { level: 'warn', text: `${value.length} characters. Bitfi devices require at least ${min}, so check for a typo.` };
  return { level: '', text: `${value.length} characters` };
}

/** Whether an address the user knows is among those checked. */
export function findAddress(value, addresses, scanned) {
  const wanted = value.trim().toLowerCase().replace(/^bitcoincash:/, '');
  if (!wanted) return { level: '', text: '' };
  const match = addresses.find(a => a.address.toLowerCase().replace(/^bitcoincash:/, '') === wanted);
  if (match) return { level: 'good', text: `This matches: ${match.label}. Your salt and secret are right.` };
  return { level: 'warn', text: `Not among positions 0 to ${scanned - 1}. Check more positions, or check the salt and secret for a typo.` };
}
