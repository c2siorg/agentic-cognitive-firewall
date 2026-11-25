// Package taint extracts value tokens from text, so the sidecar can tell
// whether a tool argument repeats a value the agent read in untrusted content.
//
// It extracts the value types an injected instruction typically redirects an
// agent to: email addresses, URLs and their hosts (with a scheme, or starting
// with "www."), IBANs, IBAN-shaped account numbers and long digit runs
// (account and phone numbers). Each token is normalised so the same value
// written two ways matches: case-folded addresses and hosts, IBANs and account
// numbers without spaces, numbers as digits only. A value of a type it does not extract, such
// as a person's name, is never tainted; that is the method's main limit.
package taint

import (
	"encoding/base64"
	"math/big"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Token is one extracted value.
type Token struct {
	// Kind is "email", "url", "host", "iban", "account" or "number".
	Kind  string
	Value string
}

// Key identifies a token across kinds, for set membership.
func (t Token) Key() string { return t.Kind + ":" + t.Value }

var (
	emailRe = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.[a-z]{2,}`)
	urlRe   = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>()\[\]{}` + "`" + `]+`)
	// wwwRe matches a link written without a scheme, such as www.example.com/a.
	// A bare domain with neither a scheme nor "www." is not extracted: it
	// cannot be told from a file name or an abbreviation.
	wwwRe    = regexp.MustCompile(`(?i)\bwww\.[a-z0-9\-]+(?:\.[a-z0-9\-]+)+(?::[0-9]+)?(?:/[^\s"'<>()\[\]{}` + "`" + `]*)?`)
	ibanRe   = regexp.MustCompile(`\b[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b`)
	numberRe = regexp.MustCompile(`\+?[0-9][0-9 ().\-]{6,}[0-9]`)
	// dateRe matches dates the number pattern would otherwise read as an
	// 8-digit number, such as 2026-10-09 or 09.10.2026.
	dateRe = regexp.MustCompile(`^(?:[0-9]{4}[-/.][0-9]{1,2}[-/.][0-9]{1,2}|[0-9]{1,2}[-/.][0-9]{1,2}[-/.][0-9]{2,4})$`)
)

// minAccountDigits is the fewest digits an IBAN-shaped string with a bad
// checksum needs to be taken for an account number.
const minAccountDigits = 10

// Extract returns the distinct tokens in text, in order of first appearance.
func Extract(text string) []Token {
	if text == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []Token
	add := func(t Token) {
		if t.Value == "" || seen[t.Key()] {
			return
		}
		seen[t.Key()] = true
		out = append(out, t)
	}

	for _, m := range emailRe.FindAllString(text, -1) {
		add(Token{Kind: "email", Value: strings.TrimRight(strings.ToLower(m), ".")})
	}
	for _, m := range urlRe.FindAllString(text, -1) {
		u, host := normaliseURL(m)
		add(Token{Kind: "url", Value: u})
		add(Token{Kind: "host", Value: host})
		// Extract nested URLs embedded inside query/path parameters (e.g.
		// open-redirect targets like https://safe.example/?next=https://evil.example).
		if schemeEnd := strings.Index(m, "://"); schemeEnd >= 0 {
			rest := m[schemeEnd+3:]
			if slash := strings.IndexAny(rest, "/?#"); slash >= 0 {
				for _, nested := range urlRe.FindAllString(rest[slash:], -1) {
					nu, nhost := normaliseURL(nested)
					add(Token{Kind: "url", Value: nu})
					add(Token{Kind: "host", Value: nhost})
				}
			}
		}
	}
	for _, m := range wwwRe.FindAllString(text, -1) {
		// Only the host: the scheme is unknown, and the host is what a link
		// with a scheme is matched on too.
		_, host := normaliseURL("http://" + m)
		add(Token{Kind: "host", Value: host})
	}
	for _, m := range ibanRe.FindAllString(text, -1) {
		iban := strings.ReplaceAll(m, " ", "")
		switch {
		case validIBAN(iban):
			add(Token{Kind: "iban", Value: iban})
		case len(digitsOnly(iban)) >= minAccountDigits:
			// An account number in IBAN form that is not a valid IBAN, such
			// as a US account written US13 3000 .... The digit floor keeps
			// out upper-case codes that merely fit the pattern.
			add(Token{Kind: "account", Value: iban})
		}
	}
	for _, m := range numberRe.FindAllString(text, -1) {
		if dateRe.MatchString(strings.TrimSpace(m)) {
			continue
		}
		if digits := digitsOnly(m); len(digits) >= 8 && len(digits) <= 20 {
			add(Token{Kind: "number", Value: digits})
		}
	}
	return out
}

// normaliseURL trims trailing punctuation a sentence leaves on a URL,
// lower-cases the scheme and host, drops the fragment and a default port, and
// returns the URL and its host without a leading "www.".
func normaliseURL(raw string) (string, string) {
	raw = strings.TrimRight(raw, ".,;:!?")
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return strings.ToLower(raw), ""
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	u.Host = host
	if port != "" {
		u.Host = host + ":" + port
	}
	u.Fragment = ""
	u.RawFragment = ""
	return u.String(), strings.TrimPrefix(host, "www.")
}

// validIBAN checks the length and the ISO 13616 mod-97 checksum, so ordinary
// upper-case codes that happen to fit the pattern are not taken for IBANs.
func validIBAN(s string) bool {
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	rearranged := s[4:] + s[:4]
	var b strings.Builder
	for _, r := range rearranged {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteString(big.NewInt(int64(r-'A') + 10).String())
		default:
			return false
		}
	}
	n, ok := new(big.Int).SetString(b.String(), 10)
	return ok && new(big.Int).Mod(n, big.NewInt(97)).Int64() == 1
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

var zeroWidthTaintRunes = map[rune]bool{
	'\u200b': true,
	'\u200c': true,
	'\u200d': true,
	'\u00ad': true,
	'\ufeff': true,
	'\u2060': true,
	'\u180e': true,
}

var base64TaintRe = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)

// NormalizeBasic strips invisible zero-width characters and applies Unicode NFKC
// normalisation without altering digits or punctuation (unlike leetspeak
// folding), so emails, URLs, IBANs and numbers remain intact.
func NormalizeBasic(text string) string {
	if text == "" {
		return ""
	}
	text = norm.NFKC.String(text)
	return strings.Map(func(r rune) rune {
		if zeroWidthTaintRunes[r] {
			return -1
		}
		return r
	}, text)
}

// ExtractClean extracts tokens from trusted text (user prompts and declared
// trusted_values) after basic Unicode and zero-width normalisation.
func ExtractClean(text string) []Token {
	return Extract(NormalizeBasic(text))
}

// ExtractUntrusted extracts tokens from untrusted content and tool call
// parameters across both basic-normalised text and de-obfuscated variants
// (recursive percent-decoding and printable Base64 decoding), so obfuscated
// addresses, IBANs and URLs cannot evade provenance tracking.
func ExtractUntrusted(text string) []Token {
	if text == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []Token
	appendDistinct := func(tokens []Token) {
		for _, tok := range tokens {
			key := tok.Key()
			if !seen[key] {
				seen[key] = true
				out = append(out, tok)
			}
		}
	}

	basic := NormalizeBasic(text)
	appendDistinct(Extract(basic))

	decoded := decodeUntrustedLayers(text)
	if decoded != text {
		if normDecoded := NormalizeBasic(decoded); normDecoded != basic {
			appendDistinct(Extract(normDecoded))
		}
	}
	return out
}

// decodeUntrustedLayers recursively percent-decodes (%XX only, keeping '+'
// intact so email+tag and +country phone prefixes are preserved) and decodes
// printable Base64 whole payloads or embedded tokens.
func decodeUntrustedLayers(text string) string {
	const maxDepth = 8
	for depth := 0; depth < maxDepth; depth++ {
		next := decodePercentOnly(text)
		next = decodeBase64ForTaint(next)
		if next == text {
			break
		}
		text = next
	}
	return text
}

func decodePercentOnly(text string) string {
	for depth := 0; depth < 8; depth++ {
		if !strings.ContainsRune(text, '%') {
			return text
		}
		var b strings.Builder
		b.Grow(len(text))
		changed := false
		for i := 0; i < len(text); {
			if text[i] == '%' && i+2 < len(text) {
				if hi, ok1 := unhexByte(text[i+1]); ok1 {
					if lo, ok2 := unhexByte(text[i+2]); ok2 {
						b.WriteByte(hi<<4 | lo)
						i += 3
						changed = true
						continue
					}
				}
			}
			b.WriteByte(text[i])
			i++
		}
		if !changed {
			return text
		}
		candidate := b.String()
		if !utf8.ValidString(candidate) {
			return text
		}
		text = candidate
	}
	return text
}

func unhexByte(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func decodeBase64ForTaint(text string) string {
	if trimmed := strings.TrimSpace(text); len(trimmed) >= 8 {
		if decoded, ok := decodePrintableBase64(trimmed); ok {
			return decoded
		}
	}
	return base64TaintRe.ReplaceAllStringFunc(text, func(tok string) string {
		if decoded, ok := decodePrintableBase64(tok); ok && (hasTokenContext(decoded) || len(Extract(decoded)) > 0) {
			return decoded
		}
		return tok
	})
}

func decodePrintableBase64(tok string) (string, bool) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		decoded, err := enc.DecodeString(tok)
		if err != nil {
			continue
		}
		s := string(decoded)
		if isPrintableUTF8(s) {
			return s, true
		}
	}
	return "", false
}

func isPrintableUTF8(s string) bool {
	if !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
		return false
	}
	for _, r := range s {
		if r == unicode.ReplacementChar || (!unicode.IsPrint(r) && !unicode.IsSpace(r)) {
			return false
		}
	}
	return len(s) > 0
}

func hasTokenContext(s string) bool {
	return strings.ContainsAny(s, " \t\r\n@:/")
}
