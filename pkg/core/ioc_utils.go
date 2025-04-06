package core

import (
	"encoding/json"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// BufferFile is the file path where extracted IOCs are saved.
var BufferFile = filepath.Join(os.Getenv("HOME"), ".cache", "ioc_buffer.json")

// IOC represents an Indicator of Compromise.
type IOC struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// DetectIOC classifies a token as a particular IOC type.
func DetectIOC(token string) (iocType, value string) {
	token = strings.TrimSpace(token)
	if ip := net.ParseIP(token); ip != nil {
		if IsPrivateIP(ip) {
			return "private_ip", token
		}
		return "ip", token
	}
	if strings.Contains(token, "@") && strings.Contains(token, ".") {
		return "email", token
	}
	parsed, err := url.Parse(token)
	if err == nil && parsed.Scheme != "" && parsed.Host != "" {
		return "url", token
	}
	if strings.Contains(token, ".") {
		parts := strings.Split(token, ".")
		if len(parts) >= 2 {
			return "domain", token
		}
	}
	re := regexp.MustCompile(`(?i:^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$)`)
	if re.MatchString(token) {
		return "hash", token
	}
	return "", token
}

// ExtractIOCs extracts IOCs from the input text.
func ExtractIOCs(text string) []IOC {
	var iocs []IOC
	re := regexp.MustCompile(`\S+`)
	tokens := re.FindAllString(text, -1)
	for _, token := range tokens {
		typ, val := DetectIOC(token)
		if typ != "" {
			iocs = append(iocs, IOC{Type: typ, Value: val})
		}
	}
	return iocs
}

// SaveBuffer writes IOCs grouped by type into BufferFile as JSON.
func SaveBuffer(iocs []IOC) error {
	grouped := make(map[string]map[string]bool)
	for _, ioc := range iocs {
		if _, exists := grouped[ioc.Type]; !exists {
			grouped[ioc.Type] = make(map[string]bool)
		}
		grouped[ioc.Type][ioc.Value] = true
	}
	result := make(map[string][]string)
	for typ, set := range grouped {
		for val := range set {
			result[typ] = append(result[typ], val)
		}
	}
	dir := filepath.Dir(BufferFile)
	os.MkdirAll(dir, 0755)
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(BufferFile, data, 0644)
}

