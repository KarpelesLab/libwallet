package wltnames

import "fmt"

// validateResolvableName is a conservative anti-homograph guard applied
// before any name (ENS / SNS) is resolved to an address that the user may
// then pay. Payment-flow name resolution is a prime target for homograph
// / confusable spoofing (e.g. a Cyrillic "а" standing in for ASCII "a",
// or mixed-script labels), so rather than attempt a full UTS-46 /
// ENSIP-15 normalization we reject anything outside a small, unambiguous
// ASCII subset. Legitimate ASCII ENS/SNS names (letters, digits, hyphen,
// underscore, dot separators) pass unchanged; anything containing
// non-ASCII or otherwise unexpected characters is refused so the UI can
// surface the typed name instead of silently resolving a look-alike.
//
// The caller is expected to display the resolved address to the user for
// confirmation; this guard only ensures the *input* label is unambiguous.
func validateResolvableName(name string) error {
	if name == "" {
		return fmt.Errorf("empty name")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			if r > 0x7f {
				return fmt.Errorf("name %q contains non-ASCII characters; refusing to resolve to avoid homograph spoofing", name)
			}
			return fmt.Errorf("name %q contains disallowed character %q", name, r)
		}
	}
	return nil
}
