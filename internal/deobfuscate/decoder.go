package deobfuscate

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// StringDecoder represents a single string decoder function found in the source.
type StringDecoder struct {
	Name string
	Key  int
}

// FindAllStringDecoders finds all string decoder functions in the source.
// Each decoder has the pattern: NAME=(function(PARAM){...s=KEY...})
// The parameter name can be any identifier, not just 'n'.
func FindAllStringDecoders(source string) []StringDecoder {
	var decoders []StringDecoder

	// Pattern: NAME=(function(PARAM){...s=NUMBER...})
	// The function body contains the rolling XOR key assignment.
	rx := regexp.MustCompile(`(\w+)=\(function\(\w+\)\{[^}]*?(\w+)=(\d+)[^}]*atob`)
	for _, m := range rx.FindAllStringSubmatch(source, -1) {
		if len(m) >= 4 {
			name := m[1]
			key, err := strconv.Atoi(m[3])
			if err != nil {
				continue
			}
			// Check if this name is used with backtick string calls.
			if regexp.MustCompile(regexp.QuoteMeta(name) + `\(\x60`).MatchString(source) {
				decoders = append(decoders, StringDecoder{Name: name, Key: key})
			}
		}
	}

	// Also check for known decoder names with default keys.
	for _, name := range []string{"aa", "a0", "b0"} {
		found := false
		for _, d := range decoders {
			if d.Name == name {
				found = true
				break
			}
		}
		if !found && regexp.MustCompile(regexp.QuoteMeta(name)+`\(\x60`).MatchString(source) {
			// Try to find the key from the source.
			keyRX := regexp.MustCompile(regexp.QuoteMeta(name) + `=\(function\(\w+\)\{[^}]*?(\w+)=(\d+)[^}]*atob`)
			if km := keyRX.FindStringSubmatch(source); len(km) >= 3 {
				if k, err := strconv.Atoi(km[2]); err == nil {
					decoders = append(decoders, StringDecoder{Name: name, Key: k})
					continue
				}
			}
			// Use default keys for known names.
			defaultKeys := map[string]int{"aa": 8185, "a0": 18103, "b0": 11889}
			if key, ok := defaultKeys[name]; ok {
				decoders = append(decoders, StringDecoder{Name: name, Key: key})
			}
		}
	}

	return decoders
}

// decodeWithKey decodes a string using the rolling XOR decoder with the given initial key.
func decodeWithKey(encoded string, initialKey int) string {
	for len(encoded)%4 != 0 {
		encoded += "="
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}

	key := uint16(initialKey)
	var result []uint16
	var buffer []uint16

	for i := 0; i < len(decoded); {
		key = (key<<8 | key>>8) & 0xFFFF
		if i >= len(decoded) {
			break
		}
		h := uint16(decoded[i]) ^ (key >> 8)
		i++
		if h == 255 {
			key = (key<<8 | key>>8) & 0xFFFF
			if i >= len(decoded) {
				break
			}
			h = uint16(decoded[i]) ^ (key >> 8)
			i++
			key = (key<<8 | key>>8) & 0xFFFF
			if i >= len(decoded) {
				break
			}
			h |= (uint16(decoded[i]) ^ (key >> 8)) << 8
			i++
		}
		buffer = append(buffer, h)
		if len(buffer) == 128 {
			result = append(result, buffer...)
			buffer = buffer[:0]
		}
	}
	result = append(result, buffer...)

	runes := make([]rune, 0, len(result))
	for _, u := range result {
		runes = append(runes, rune(u))
	}
	return string(runes)
}

// DecodeAaString decodes a string using the aa() obfuscation with key 8185.
func DecodeAaString(encoded string) string {
	return decodeWithKey(encoded, 8185)
}

// DecodeA0String decodes a string using the a0() obfuscation with key 18103.
func DecodeA0String(encoded string) string {
	return decodeWithKey(encoded, 18103)
}

// decodeAllStringCalls decodes all string decoder calls using all found decoders.
func (d *Deobfuscator) decodeAllStringCalls(source string, decoders []StringDecoder) string {
	result := source
	for _, dec := range decoders {
		pattern := regexp.MustCompile(regexp.QuoteMeta(dec.Name) + `\(\x60([^\x60]+)\x60\)`)
		result = pattern.ReplaceAllStringFunc(result, func(s string) string {
			m := pattern.FindStringSubmatch(s)
			if len(m) < 2 {
				return s
			}
			encoded := m[1]
			cacheKey := fmt.Sprintf("%s:%s", dec.Name, encoded)
			if decoded, ok := d.StringCache[cacheKey]; ok {
				escaped := strings.ReplaceAll(decoded, "`", "\\`")
				return "`" + escaped + "`"
			}
			decoded := decodeWithKey(encoded, dec.Key)
			if decoded != "" {
				d.StringCache[cacheKey] = decoded
				escaped := strings.ReplaceAll(decoded, "`", "\\`")
				return "`" + escaped + "`"
			}
			return s
		})
	}
	return result
}

// findStringDecoders finds all string decoder functions and sets the primary one.
func (d *Deobfuscator) findStringDecoders(source string) []StringDecoder {
	decoders := FindAllStringDecoders(source)
	if len(decoders) > 0 {
		d.StringDecoderName = decoders[0].Name
		d.StringDecoderKey = decoders[0].Key
	}
	return decoders
}

// findStringDecoder finds the name of the string decoder function and its key.
func (d *Deobfuscator) findStringDecoder(source string) {
	decoders := d.findStringDecoders(source)
	_ = decoders // Used by decodeAllStringCalls
}

// decodeStringCalls finds and decodes all string decoder calls using all decoders.
func (d *Deobfuscator) decodeStringCalls(source string) string {
	decoders := d.findStringDecoders(source)
	if len(decoders) == 0 {
		return source
	}
	return d.decodeAllStringCalls(source, decoders)
}
