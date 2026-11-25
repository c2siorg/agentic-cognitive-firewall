// normalise.go — Stage 2 of the pipeline.
// Produces canonical text for scanning by applying (in order):
//  1. Recursive URL decoding
//  2. Recursive Base64 decoding
//  3. Unicode NFKC normalisation
//  4. Zero-width character stripping
//  5. Whitespace collapsing
//  6. Leetspeak cleaning
//
// The result is written to rc.CanonicalText. The original rc.Payload is never
// mutated. Normalise never emits a hard block signal — it is a pure transform.
package pipeline

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// zeroWidthChars is the set of Unicode code points that are invisible and
// commonly used to bypass keyword detection.
var zeroWidthChars = []rune{
	'\u200b', // zero-width space
	'\u200c', // zero-width non-joiner
	'\u200d', // zero-width joiner
	'\u00ad', // soft hyphen
	'\ufeff', // BOM / zero-width no-break space
	'\u2060', // word joiner
	'\u180e', // mongolian vowel separator
}

var zeroWidthSet = func() map[rune]bool {
	m := make(map[rune]bool, len(zeroWidthChars))
	for _, r := range zeroWidthChars {
		m[r] = true
	}
	return m
}()

// leetspeakMap maps common leet substitutions to their ASCII equivalents.
var leetspeakMap = map[rune]rune{
	'0': 'o',
	'1': 'l',
	'3': 'e',
	'4': 'a',
	'5': 's',
	'7': 't',
	'@': 'a',
	'$': 's',
	'!': 'i',
}

// NormaliseStage produces canonical text from the inbound payload.
type NormaliseStage struct{}

func (n *NormaliseStage) Name() string { return "normalise" }

// Run extracts text from rc.Payload, applies all normalisation transforms,
// and writes the result to rc.CanonicalText. Always returns hardBlock=false.
func (n *NormaliseStage) Run(rc *riskcontext.RiskContext) (hardBlock bool) {
	raw := payloadText(rc.Payload)
	rc.CanonicalText = normalise(raw)
	return false
}

// NewNormaliseStage constructs a NormaliseStage.
func NewNormaliseStage() *NormaliseStage {
	return &NormaliseStage{}
}

// payloadText extracts a deterministic string representation from the payload.
// For string payloads, returns the string directly.
// For map payloads, recursively flattens all string leaves in sorted key order
// (including nested maps and arrays such as on_tool_call params).
// For other types, uses fmt.Sprintf as a best-effort fallback.
func payloadText(payload any) string {
	switch v := payload.(type) {
	case string:
		return v
	case map[string]any:
		return flattenStrings(v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// sanitiseTargetField mirrors policy.payloadFieldAndText so the scan stage
// maps matches against the same primary text field that ApplySanitise edits.
func sanitiseTargetField(payload any) (field, text string, ok bool) {
	switch v := payload.(type) {
	case string:
		return "", v, true
	case map[string]any:
		for _, key := range []string{"content", "value", "text", "prompt", "result"} {
			if s, found := v[key].(string); found {
				return key, s, true
			}
		}
	}
	return "", "", false
}

// normalise applies all transforms to text and returns the canonical form.
func normalise(text string) string {
	text = decodeURL(text)
	text = decodeBase64(text)
	text = applyNFKC(text)
	text = stripZeroWidth(text)
	text = collapseWhitespace(text)
	text = cleanLeetspeak(text)
	return text
}

// decodeURL repeatedly URL-decodes text until stable.
func decodeURL(text string) string {
	for {
		decoded, err := url.QueryUnescape(text)
		if err != nil || decoded == text {
			return text
		}
		text = decoded
	}
}

// decodeBase64 recursively decodes base64-encoded content. Each pass first
// tries to decode the whole payload, then falls back to decoding individual
// base64 tokens embedded in a larger string. It loops until neither pass
// changes the text, so nested encodings and multiple tokens are all resolved.
func decodeBase64(text string) string {
	for {
		decoded := tryBase64(text)
		if decoded == text {
			decoded = decodeBase64Tokens(text)
		}
		if decoded == text {
			return text
		}
		text = decoded
	}
}

// base64TokenRe matches a run of base64 characters long enough to plausibly
// carry an encoded instruction. The class covers both the standard (+/) and
// URL-safe (-_) alphabets so url-safe tokens are not skipped. Short runs are
// left alone to avoid touching ordinary words and identifiers.
var base64TokenRe = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)

// decodeBase64Tokens decodes base64 tokens that sit inside a larger payload,
// which the whole-string tryBase64 pass cannot reach. Only tokens that decode
// to a printable phrase are replaced; benign tokens (ids, hashes, opaque
// blobs) are left as-is so canonical text for clean traffic is unchanged.
func decodeBase64Tokens(text string) string {
	return base64TokenRe.ReplaceAllStringFunc(text, func(tok string) string {
		if decoded, ok := tryBase64Token(tok); ok {
			return decoded
		}
		return tok
	})
}

// tryBase64Token decodes a single token and reports whether the result looks
// like encoded text worth scanning. It is deliberately strict: the decode must
// be printable UTF-8 and read like a phrase (a space plus a letter), which is
// what encoded injections look like and what random base64 blobs do not.
func tryBase64Token(tok string) (string, bool) {
	decoded, ok := decodeAnyBase64(tok)
	if !ok {
		return "", false
	}
	s := string(decoded)
	if !isPrintableUTF8(s) || !looksLikePhrase(s) {
		return "", false
	}
	return s, true
}

// decodeAnyBase64 tries the standard and URL-safe alphabets, padded and
// unpadded, and returns the first that decodes. URL-safe (-_) is the case the
// standard-only decoder missed, where a url-safe token slipped past the scanner.
func decodeAnyBase64(tok string) ([]byte, bool) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := enc.DecodeString(tok); err == nil {
			return decoded, true
		}
	}
	return nil, false
}

// looksLikePhrase returns true if s reads like natural-language text: it has at
// least one space and at least one letter. This keeps the token decoder from
// rewriting base64 that happens to decode to opaque bytes.
func looksLikePhrase(s string) bool {
	hasSpace, hasLetter := false, false
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			hasSpace = true
		case unicode.IsLetter(r):
			hasLetter = true
		}
		if hasSpace && hasLetter {
			return true
		}
	}
	return false
}

// tryBase64 attempts to base64-decode text. Returns the decoded string if
// successful and the result is printable ASCII/UTF-8, otherwise returns text.
func tryBase64(text string) string {
	// Only attempt if the text looks like a base64 candidate (length divisible
	// by 4 after stripping whitespace, or padded).
	candidate := strings.TrimSpace(text)
	if len(candidate) < 4 {
		return text
	}
	decoded, err := base64.StdEncoding.DecodeString(candidate)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(candidate)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(candidate)
			if err != nil {
				return text
			}
		}
	}
	// Only accept the decoded form if it is valid UTF-8 and contains printable chars.
	result := string(decoded)
	if !isPrintableUTF8(result) {
		return text
	}
	return result
}

// isPrintableUTF8 returns true if s is valid UTF-8 containing at least some
// printable characters and no null bytes.
func isPrintableUTF8(s string) bool {
	if strings.ContainsRune(s, 0) {
		return false
	}
	printable := 0
	for _, r := range s {
		if r == unicode.ReplacementChar {
			return false
		}
		if unicode.IsPrint(r) {
			printable++
		}
	}
	return printable > 0
}

// applyNFKC applies Unicode NFKC normalisation, which decomposes compatibility
// characters and recomposes them in canonical form. This collapses ligatures,
// full-width characters, and other visual equivalents.
func applyNFKC(text string) string {
	return norm.NFKC.String(text)
}

// stripZeroWidth removes all zero-width and invisible Unicode characters.
func stripZeroWidth(text string) string {
	return strings.Map(func(r rune) rune {
		if zeroWidthSet[r] {
			return -1 // drop
		}
		return r
	}, text)
}

// collapseWhitespace replaces every run of whitespace with one space. Patterns
// are phrases with single spaces, so without this a phrase split by a line
// break, a tab or extra spaces does not match: tool output formatted as YAML
// or JSON wraps long lines, and an attacker can add a newline on purpose.
func collapseWhitespace(text string) string {
	var b strings.Builder
	b.Grow(len(text))
	inSpace := false
	for _, r := range text {
		if unicode.IsSpace(r) {
			if !inSpace {
				b.WriteByte(' ')
				inSpace = true
			}
			continue
		}
		inSpace = false
		b.WriteRune(r)
	}
	return b.String()
}

// normalisePattern applies only the character-level transforms that also run
// on payloads, so the AC dictionary and CanonicalText use the same alphabet.
// URL and base64 decoding are skipped because those are payload-specific.
func normalisePattern(p string) string {
	p = applyNFKC(p)
	p = stripZeroWidth(p)
	p = collapseWhitespace(p)
	p = cleanLeetspeak(p)
	return p
}

// cleanLeetspeak replaces common leet substitutions with their ASCII equivalents.
func cleanLeetspeak(text string) string {
	return strings.Map(func(r rune) rune {
		if mapped, ok := leetspeakMap[r]; ok {
			return mapped
		}
		return r
	}, text)
}

// byteSpan records the half-open byte range [start, end) in the original string
// that produced a byte in the transformed string.
type byteSpan struct {
	start int
	end   int
}

type trackedText struct {
	text  string
	spans []byteSpan
}

func newTrackedText(raw string) trackedText {
	spans := make([]byteSpan, len(raw))
	for i := 0; i < len(raw); i++ {
		spans[i] = byteSpan{start: i, end: i + 1}
	}
	return trackedText{text: raw, spans: spans}
}

func mergeByteSpans(slice []byteSpan) byteSpan {
	if len(slice) == 0 {
		return byteSpan{}
	}
	out := slice[0]
	for _, s := range slice[1:] {
		if s.start < out.start {
			out.start = s.start
		}
		if s.end > out.end {
			out.end = s.end
		}
	}
	return out
}

func appendRepeatedSpan(dst []byteSpan, s byteSpan, count int) []byteSpan {
	for i := 0; i < count; i++ {
		dst = append(dst, s)
	}
	return dst
}

// normaliseTracked mirrors normalise(raw) while maintaining per-byte provenance
// spans back to raw so matched canonical spans can be redacted in original text.
func normaliseTracked(raw string) trackedText {
	tt := newTrackedText(raw)
	tt = decodeURLTracked(tt)
	tt = decodeBase64Tracked(tt)
	tt = applyNFKCTracked(tt)
	tt = stripZeroWidthTracked(tt)
	tt = collapseWhitespaceTracked(tt)
	tt = cleanLeetspeakTracked(tt)
	return tt
}

func decodeURLTracked(tt trackedText) trackedText {
	for {
		if !strings.ContainsAny(tt.text, "%+") {
			return tt
		}
		next, ok := unescapeQueryTracked(tt)
		if !ok || next.text == tt.text {
			return tt
		}
		tt = next
	}
}

func unescapeQueryTracked(tt trackedText) (trackedText, bool) {
	buf := make([]byte, 0, len(tt.text))
	spans := make([]byteSpan, 0, len(tt.text))
	for i := 0; i < len(tt.text); {
		switch tt.text[i] {
		case '+':
			buf = append(buf, ' ')
			spans = append(spans, tt.spans[i])
			i++
		case '%':
			if i+2 >= len(tt.text) {
				return tt, false
			}
			hi, ok1 := unhexNibble(tt.text[i+1])
			lo, ok2 := unhexNibble(tt.text[i+2])
			if !ok1 || !ok2 {
				return tt, false
			}
			buf = append(buf, hi<<4|lo)
			spans = append(spans, mergeByteSpans(tt.spans[i:i+3]))
			i += 3
		default:
			buf = append(buf, tt.text[i])
			spans = append(spans, tt.spans[i])
			i++
		}
	}
	return trackedText{text: string(buf), spans: spans}, true
}

func unhexNibble(c byte) (byte, bool) {
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

func decodeBase64Tracked(tt trackedText) trackedText {
	for {
		if decoded := tryBase64(tt.text); decoded != tt.text {
			lead := len(tt.text) - len(strings.TrimLeftFunc(tt.text, unicode.IsSpace))
			trail := len(strings.TrimRightFunc(tt.text, unicode.IsSpace))
			if lead >= trail {
				lead, trail = 0, len(tt.text)
			}
			wholeSpan := mergeByteSpans(tt.spans[lead:trail])
			spans := appendRepeatedSpan(make([]byteSpan, 0, len(decoded)), wholeSpan, len(decoded))
			tt = trackedText{text: decoded, spans: spans}
			continue
		}
		next, changed := decodeBase64TokensTracked(tt)
		if !changed {
			return tt
		}
		tt = next
	}
}

func decodeBase64TokensTracked(tt trackedText) (trackedText, bool) {
	matches := base64TokenRe.FindAllStringIndex(tt.text, -1)
	if len(matches) == 0 {
		return tt, false
	}
	var buf strings.Builder
	buf.Grow(len(tt.text))
	spans := make([]byteSpan, 0, len(tt.text))
	prev := 0
	changed := false
	for _, m := range matches {
		start, end := m[0], m[1]
		if start > prev {
			buf.WriteString(tt.text[prev:start])
			spans = append(spans, tt.spans[prev:start]...)
		}
		if decoded, ok := tryBase64Token(tt.text[start:end]); ok {
			tokSpan := mergeByteSpans(tt.spans[start:end])
			buf.WriteString(decoded)
			spans = appendRepeatedSpan(spans, tokSpan, len(decoded))
			changed = true
		} else {
			buf.WriteString(tt.text[start:end])
			spans = append(spans, tt.spans[start:end]...)
		}
		prev = end
	}
	if !changed {
		return tt, false
	}
	if prev < len(tt.text) {
		buf.WriteString(tt.text[prev:])
		spans = append(spans, tt.spans[prev:]...)
	}
	return trackedText{text: buf.String(), spans: spans}, true
}

func applyNFKCTracked(tt trackedText) trackedText {
	if utf8.ValidString(tt.text) && norm.NFKC.IsNormalString(tt.text) {
		return tt
	}
	buf := make([]byte, 0, len(tt.text))
	spans := make([]byteSpan, 0, len(tt.text))
	for pos := 0; pos < len(tt.text); {
		r, w := utf8.DecodeRuneInString(tt.text[pos:])
		if r == utf8.RuneError && w == 1 {
			const rep = "\ufffd"
			buf = append(buf, rep...)
			spans = appendRepeatedSpan(spans, tt.spans[pos], len(rep))
			pos++
			continue
		}
		next := norm.NFKC.NextBoundaryInString(tt.text[pos:], true)
		if next <= 0 {
			next = len(tt.text) - pos
		}
		// Keep valid prefix separate if an invalid UTF-8 byte falls before the next NFKC boundary.
		seg := tt.text[pos : pos+next]
		if !utf8.ValidString(seg) {
			validEnd := 0
			for validEnd < len(seg) {
				sr, sw := utf8.DecodeRuneInString(seg[validEnd:])
				if sr == utf8.RuneError && sw == 1 {
					break
				}
				validEnd += sw
			}
			if validEnd > 0 {
				next = validEnd
				seg = seg[:validEnd]
			}
		}
		normSeg := norm.NFKC.String(seg)
		if seg == normSeg {
			buf = append(buf, seg...)
			spans = append(spans, tt.spans[pos:pos+next]...)
		} else {
			segSpan := mergeByteSpans(tt.spans[pos : pos+next])
			buf = append(buf, normSeg...)
			spans = appendRepeatedSpan(spans, segSpan, len(normSeg))
		}
		pos += next
	}
	return trackedText{text: string(buf), spans: spans}
}

func stripZeroWidthTracked(tt trackedText) trackedText {
	var buf strings.Builder
	buf.Grow(len(tt.text))
	spans := make([]byteSpan, 0, len(tt.text))
	for i, r := range tt.text {
		_, w := utf8.DecodeRuneInString(tt.text[i:])
		if zeroWidthSet[r] {
			continue
		}
		buf.WriteString(tt.text[i : i+w])
		spans = append(spans, tt.spans[i:i+w]...)
	}
	return trackedText{text: buf.String(), spans: spans}
}

func collapseWhitespaceTracked(tt trackedText) trackedText {
	var buf strings.Builder
	buf.Grow(len(tt.text))
	spans := make([]byteSpan, 0, len(tt.text))
	inSpace := false
	spaceIdx := -1
	for i, r := range tt.text {
		w := utf8.RuneLen(r)
		if r == utf8.RuneError {
			_, w = utf8.DecodeRuneInString(tt.text[i:])
		}
		sp := mergeByteSpans(tt.spans[i : i+w])
		if unicode.IsSpace(r) {
			if !inSpace {
				buf.WriteByte(' ')
				spans = append(spans, sp)
				spaceIdx = len(spans) - 1
				inSpace = true
			} else {
				spans[spaceIdx] = mergeByteSpans([]byteSpan{spans[spaceIdx], sp})
			}
			continue
		}
		inSpace = false
		buf.WriteString(tt.text[i : i+w])
		spans = append(spans, tt.spans[i:i+w]...)
	}
	return trackedText{text: buf.String(), spans: spans}
}

func cleanLeetspeakTracked(tt trackedText) trackedText {
	return mapRunesTracked(tt, func(r rune) rune {
		if mapped, ok := leetspeakMap[r]; ok {
			return mapped
		}
		return r
	})
}

func toLowerTracked(tt trackedText) trackedText {
	return mapRunesTracked(tt, unicode.ToLower)
}

func mapRunesTracked(tt trackedText, fn func(rune) rune) trackedText {
	var buf strings.Builder
	buf.Grow(len(tt.text))
	spans := make([]byteSpan, 0, len(tt.text))
	var tmp [utf8.UTFMax]byte
	for i, r := range tt.text {
		w := utf8.RuneLen(r)
		if r == utf8.RuneError {
			_, w = utf8.DecodeRuneInString(tt.text[i:])
		}
		mapped := fn(r)
		if mapped == r {
			buf.WriteString(tt.text[i : i+w])
			spans = append(spans, tt.spans[i:i+w]...)
			continue
		}
		n := utf8.EncodeRune(tmp[:], mapped)
		buf.Write(tmp[:n])
		sp := mergeByteSpans(tt.spans[i : i+w])
		spans = appendRepeatedSpan(spans, sp, n)
	}
	return trackedText{text: buf.String(), spans: spans}
}
