package core

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Constants for VirusTotal endpoints.
const (
	VTFileURL   = "https://www.virustotal.com/api/v3/files/%s"
	VTURLLookup = "https://www.virustotal.com/api/v3/urls/%s"
	VTDomainURL = "https://www.virustotal.com/api/v3/domains/%s"
	VTIPURL     = "https://www.virustotal.com/api/v3/ip_addresses/%s"
)

// QueryVTIP queries VirusTotal for an IP address.
func QueryVTIP(ip, apiKey string, maxRetries int) (map[string]interface{}, error) {
	headers := map[string]string{"x-apikey": apiKey}
	url := fmt.Sprintf(VTIPURL, ip)
	body, err := fetchWithRetries(url, headers, nil, maxRetries, 1)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	if data, ok := result["data"].(map[string]interface{}); ok {
		if attributes, ok := data["attributes"].(map[string]interface{}); ok {
			attributes["timestamp"] = float64(time.Now().Unix())
			return attributes, nil
		}
	}
	return nil, errors.New("unexpected response from VT IP endpoint")
}

// QueryVTFile queries VirusTotal for a file hash and returns the full attributes.
func QueryVTFile(hash, apiKey string, maxRetries int) (map[string]interface{}, error) {
	headers := map[string]string{"x-apikey": apiKey}
	url := fmt.Sprintf(VTFileURL, hash)
	body, err := fetchWithRetries(url, headers, nil, maxRetries, 1)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	if data, ok := result["data"].(map[string]interface{}); ok {
		if attributes, ok := data["attributes"].(map[string]interface{}); ok {
			attributes["timestamp"] = float64(time.Now().Unix())
			// Return the full attributes map without limiting the keys.
			return attributes, nil
		}
	}
	return nil, errors.New("unexpected response from VT File endpoint")
}

// QueryVTURL queries VirusTotal for a URL.
func QueryVTURL(urlStr, apiKey string, maxRetries int) (map[string]interface{}, error) {
	headers := map[string]string{"x-apikey": apiKey}
	encoded := base64.URLEncoding.EncodeToString([]byte(urlStr))
	encoded = strings.TrimRight(encoded, "=")
	endpoint := fmt.Sprintf(VTURLLookup, encoded)
	body, err := fetchWithRetries(endpoint, headers, nil, maxRetries, 1)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	if data, ok := result["data"].(map[string]interface{}); ok {
		if attributes, ok := data["attributes"].(map[string]interface{}); ok {
			attributes["timestamp"] = float64(time.Now().Unix())
			return attributes, nil
		}
	}
	return nil, errors.New("unexpected response from VT URL endpoint")
}

// QueryVTDomain queries VirusTotal for a domain.
func QueryVTDomain(domain, apiKey string, maxRetries int) (map[string]interface{}, error) {
	headers := map[string]string{"x-apikey": apiKey}
	url := fmt.Sprintf(VTDomainURL, domain)
	body, err := fetchWithRetries(url, headers, nil, maxRetries, 1)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	if data, ok := result["data"].(map[string]interface{}); ok {
		if attributes, ok := data["attributes"].(map[string]interface{}); ok {
			attributes["timestamp"] = float64(time.Now().Unix())
			return attributes, nil
		}
	}
	return nil, errors.New("unexpected response from VT Domain endpoint")
}

