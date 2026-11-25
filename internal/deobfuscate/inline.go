package deobfuscate

import (
	"fmt"
	"regexp"
	"strings"
)

// InlineAccessors finds and inlines simple accessor functions in the source.
func InlineAccessors(source string) (string, error) {
	accessors := make(map[string]string)

	// Regex-based accessor finding.
	rxAssign := regexp.MustCompile(`(\w+)=function\((\w+)\)\{return \w+\[(\d+)\]\}`)
	for _, m := range rxAssign.FindAllStringSubmatch(source, -1) {
		if len(m) >= 4 {
			accessors[m[1]] = fmt.Sprintf("%s[%s]", m[2], m[3])
		}
	}
	rxPropAssign := regexp.MustCompile(`(\w+)=function\((\w+)\)\{return \w+\.(\w+)\}`)
	for _, m := range rxPropAssign.FindAllStringSubmatch(source, -1) {
		if len(m) >= 4 {
			accessors[m[1]] = fmt.Sprintf("%s.%s", m[2], m[3])
		}
	}
	rxCmpAssign := regexp.MustCompile(`(\w+)=function\((\w+),(\w+)\)\{return (\w+)([<>=!]+)(\w+)\}`)
	for _, m := range rxCmpAssign.FindAllStringSubmatch(source, -1) {
		if len(m) >= 7 {
			accessors[m[1]] = fmt.Sprintf("%s%s%s", m[4], m[5], m[6])
		}
	}

	if len(accessors) == 0 {
		return source, nil
	}

	// Inline calls to accessor functions.
	result := source
	for name, template := range accessors {
		pattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\(([^()]+)\)`)
		result = pattern.ReplaceAllStringFunc(result, func(s string) string {
			m := pattern.FindStringSubmatch(s)
			if len(m) < 2 {
				return s
			}
			arg := m[1]
			return inlineCall(template, arg)
		})
	}

	return result, nil
}

func inlineCall(template, arg string) string {
	rxParam := regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*)`)
	m := rxParam.FindStringSubmatch(template)
	if len(m) < 2 {
		return template
	}
	paramName := m[1]
	rxReplace := regexp.MustCompile(`\b` + regexp.QuoteMeta(paramName) + `\b`)
	return rxReplace.ReplaceAllString(template, arg)
}

func DeobfuscateWithInlining(source string) (string, error) {
	result, err := DeobfuscateScript(source)
	if err != nil {
		return "", err
	}
	result, err = InlineAccessors(result)
	if err != nil {
		return result, nil
	}
	return result, nil
}

func ExtractSessionConfig(source string) map[string]string {
	config := make(map[string]string)
	rx := regexp.MustCompile(`window\._cf_chl_opt\.(\w+)\s*=\s*([^;]+)`)
	for _, m := range rx.FindAllStringSubmatch(source, -1) {
		if len(m) >= 3 {
			config[m[1]] = strings.TrimSpace(m[2])
		}
	}
	return config
}
