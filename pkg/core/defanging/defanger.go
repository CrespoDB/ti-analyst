package defanging

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

// DefangToken defangs a single token.
func DefangToken(token string) string {
	token = strings.TrimSpace(token)
	if ip := net.ParseIP(token); ip != nil {
		if ip.To4() != nil {
			return strings.ReplaceAll(token, ".", "[.]")
		}
		return strings.ReplaceAll(token, ":", "[:]")
	}
	if strings.Contains(token, "@") && strings.Contains(token, ".") {
		return strings.ReplaceAll(token, "@", "[at]")
	}
	parsed, err := url.Parse(token)
	if err == nil && parsed.Scheme != "" && parsed.Host != "" {
		defangedScheme := strings.Replace(parsed.Scheme, "http", "hxxp", 1)
		defangedHost := strings.ReplaceAll(parsed.Host, ".", "[.]")
		newURL := defangedScheme + "://" + defangedHost + parsed.Path
		if parsed.RawQuery != "" {
			newURL += "?" + parsed.RawQuery
		}
		if parsed.Fragment != "" {
			newURL += "#" + parsed.Fragment
		}
		return newURL
	}
	if strings.Contains(token, ".") {
		return strings.ReplaceAll(token, ".", "[.]")
	}
	return token
}

// RefangToken reverses the defanging process.
func RefangToken(token string) string {
	token = strings.ReplaceAll(token, "[at]", "@")
	token = strings.ReplaceAll(token, "[.]", ".")
	token = strings.ReplaceAll(token, "[:]", ":")
	re := regexp.MustCompile(`\bhxxp(s?)\b`)
	return re.ReplaceAllString(token, "http$1")
}

// DefangText applies defanging to all non-whitespace tokens.
func DefangText(text string) string {
	re := regexp.MustCompile(`\S+`)
	return re.ReplaceAllStringFunc(text, DefangToken)
}

// RefangText applies refanging to all non-whitespace tokens.
func RefangText(text string) string {
	re := regexp.MustCompile(`\S+`)
	return re.ReplaceAllStringFunc(text, RefangToken)
}

