package wltswap

// Swap:countryAvailability — country-keyed feature gate. Hosts call
// this from settings / onboarding to decide whether the Swap UI
// should be visible at all for the user's jurisdiction, independent
// of which network they happen to be on. Country comes from the
// host (locale, geo-IP, account profile — caller's choice); we
// don't sniff it.
//
// Source of truth for the allow-list is OKX's public app-
// availability page, https://www.okx.com/app-availability/ios,
// last reviewed against the 2025-05-22 update. The list is the
// "Countries and regions where OKX is available" section verbatim,
// mapped to ISO 3166-1 alpha-2 codes. Refresh by re-fetching the
// page and reconciling against okxAvailableCountries below.
//
// Stays a static allow-list so the check is a cheap predicate the
// host can call from anywhere — no RPC, no DB, no geo lookup.

import (
	"context"
	"errors"
	"strings"

	"github.com/KarpelesLab/countrydb"
)

// CountryAvailabilityRequest is the input to Swap:countryAvailability.
// Country accepts ISO 3166-1 alpha-2 (canonical) case-insensitively
// — host code that already speaks the alpha-2 idiom doesn't have to
// case-normalize before calling.
type CountryAvailabilityRequest struct {
	Country string `json:"country"`
}

// CountryAvailabilityResult is the response from
// Swap:countryAvailability.
//
//	available : true iff the country is on the OKX allow-list.
//	country   : echo of the (normalized, uppercase) alpha-2 code.
//	reason    : stable short string when available=false. Values:
//	            "invalid_country"      — code didn't parse / isn't
//	                                     a recognised alpha-2.
//	            "country_not_supported" — code is valid but not on
//	                                     OKX's published list.
type CountryAvailabilityResult struct {
	Available bool   `json:"available"`
	Country   string `json:"country,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// okxAvailableCountries is the OKX iOS app's allow-list verbatim
// from https://www.okx.com/app-availability/ios (page snapshot
// 2025-05-22), translated to ISO 3166-1 alpha-2.
//
// Update protocol:
//  1. Refresh the OKX page above; diff the visible list against
//     this map.
//  2. Add or remove rows so this map exactly matches the published
//     allow-list. Stays in alphabetic-by-alpha2 order for
//     diff-friendliness.
//  3. Run TestOkxAvailableCountries_CountMatches; bump the constant
//     to the new size.
//
// Entries are anchored to a known countrydb row so a typo in the
// alpha-2 trips the init-time assertion below — silent drift of
// the country list against the host's geo data is the failure mode
// we care about.
var okxAvailableCountries = map[string]bool{
	"AE": true, // United Arab Emirates
	"AG": true, // Antigua and Barbuda
	"AI": true, // Anguilla
	"AM": true, // Armenia
	"AR": true, // Argentina
	"AT": true, // Austria
	"AU": true, // Australia
	"AZ": true, // Azerbaijan
	"BB": true, // Barbados
	"BE": true, // Belgium
	"BG": true, // Bulgaria
	"BH": true, // Bahrain
	"BM": true, // Bermuda
	"BO": true, // Bolivia
	"BR": true, // Brazil
	"BS": true, // Bahamas
	"BW": true, // Botswana
	"BY": true, // Belarus
	"BZ": true, // Belize
	"CA": true, // Canada
	"CF": true, // Central African Republic
	"CH": true, // Switzerland
	"CI": true, // Côte d'Ivoire
	"CL": true, // Chile
	"CM": true, // Cameroon
	"CO": true, // Colombia
	"CR": true, // Costa Rica
	"CZ": true, // Czech Republic
	"DE": true, // Germany
	"DK": true, // Denmark
	"DM": true, // Dominica
	"DO": true, // Dominican Republic
	"EC": true, // Ecuador
	"EE": true, // Estonia
	"ES": true, // Spain
	"FI": true, // Finland
	"FR": true, // France
	"GB": true, // United Kingdom
	"GD": true, // Grenada
	"GE": true, // Georgia
	"GN": true, // Guinea
	"GQ": true, // Equatorial Guinea
	"GR": true, // Greece
	"GT": true, // Guatemala
	"GW": true, // Guinea-Bissau
	"GY": true, // Guyana
	"HK": true, // Hong Kong (China)
	"HN": true, // Honduras
	"HR": true, // Croatia
	"HU": true, // Hungary
	"IE": true, // Ireland
	"IL": true, // Israel
	"IT": true, // Italy
	"JM": true, // Jamaica
	"JO": true, // Jordan
	"JP": true, // Japan
	"KE": true, // Kenya
	"KG": true, // Kyrgyzstan
	"KN": true, // Saint Kitts and Nevis
	"KR": true, // South Korea
	"KW": true, // Kuwait
	"KY": true, // Cayman Islands
	"KZ": true, // Kazakhstan
	"LC": true, // Saint Lucia
	"LI": true, // Liechtenstein
	"LT": true, // Lithuania
	"LU": true, // Luxembourg
	"LV": true, // Latvia
	"MA": true, // Morocco
	"MD": true, // Moldova
	"ME": true, // Montenegro
	"MG": true, // Madagascar
	"MK": true, // Macedonia
	"ML": true, // Mali
	"MO": true, // Macau (China)
	"MT": true, // Malta
	"MU": true, // Mauritius
	"MX": true, // Mexico
	"MY": true, // Malaysia
	"MZ": true, // Mozambique
	"NE": true, // Niger
	"NG": true, // Nigeria
	"NI": true, // Nicaragua
	"NL": true, // Netherlands
	"NO": true, // Norway
	"NZ": true, // New Zealand
	"OM": true, // Oman
	"PA": true, // Panama
	"PE": true, // Peru
	"PL": true, // Poland
	"PR": true, // Puerto Rico
	"PT": true, // Portugal
	"PY": true, // Paraguay
	"QA": true, // Qatar
	"RO": true, // Romania
	"RU": true, // Russia
	"SA": true, // Saudi Arabia
	"SE": true, // Sweden
	"SG": true, // Singapore
	"SI": true, // Slovenia
	"SK": true, // Slovakia
	"SN": true, // Senegal
	"SR": true, // Suriname
	"SV": true, // El Salvador
	"TC": true, // Turks and Caicos
	"TJ": true, // Tajikistan
	"TM": true, // Turkmenistan
	"TN": true, // Tunisia
	"TR": true, // Türkiye
	"TT": true, // Trinidad and Tobago
	"TW": true, // Taiwan (China)
	"UA": true, // Ukraine
	"UG": true, // Uganda
	"US": true, // United States
	"UY": true, // Uruguay
	"UZ": true, // Uzbekistan
	"VC": true, // Saint Vincent and the Grenadines
	"VE": true, // Venezuela
	"VG": true, // British Virgin Islands
	"VN": true, // Vietnam
	"ZA": true, // South Africa
}

// okxAvailableCountryCount is pinned so a regression that
// silently drops a row or duplicates one shows up as a count
// mismatch in tests rather than a quiet downgrade.
const okxAvailableCountryCount = 121

func init() {
	// Self-check: every code in the allow-list must resolve in
	// countrydb. A typo (e.g. "GR" → "GG" by accident, or "MK" vs
	// "MK") would silently exclude users from the right country, so
	// fail loud at process start instead.
	for code := range okxAvailableCountries {
		if _, ok := countrydb.ByAlpha2[code]; !ok {
			panic("wltswap: unknown ISO 3166-1 alpha-2 in okxAvailableCountries: " + code)
		}
	}
}

// swapCountryAvailability is the Swap:countryAvailability handler.
// Pure local check — no RPC, no DB lookup beyond the static
// countrydb. The host is responsible for sourcing the country
// (locale, geo-IP, account profile, or the user picking it
// manually); we don't sniff it because libwallet doesn't have a
// canonical "where is this user" signal.
func swapCountryAvailability(ctx context.Context, req *CountryAvailabilityRequest) (any, error) {
	if req == nil {
		return nil, errors.New("country is required")
	}
	code := strings.ToUpper(strings.TrimSpace(req.Country))
	res := &CountryAvailabilityResult{Country: code}
	if code == "" {
		res.Reason = "invalid_country"
		return res, nil
	}
	if _, ok := countrydb.ByAlpha2[code]; !ok {
		res.Reason = "invalid_country"
		return res, nil
	}
	if okxAvailableCountries[code] {
		res.Available = true
		return res, nil
	}
	res.Reason = "country_not_supported"
	return res, nil
}
