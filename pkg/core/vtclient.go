package core

import (
	"context"
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

// queryVT is a helper that performs a VirusTotal API query, unmarshals the response,
// extracts the "attributes" field, and adds a timestamp.
func queryVT(ctx context.Context, endpoint, apiKey string, maxRetries int, endpointName string) (map[string]interface{}, error) {
	headers := map[string]string{"x-apikey": apiKey}
	// Call fetchWithRetries with context support.
	body, err := fetchWithRetries(ctx, endpoint, headers, nil, maxRetries, 1)
	if err != nil {
		return nil, fmt.Errorf("%s error: %w", endpointName, err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("%s unmarshal error: %w", endpointName, err)
	}
	data, ok := result["data"].(map[string]interface{})
	if !ok {
		return nil, errors.New("unexpected response: missing data field")
	}
	attributes, ok := data["attributes"].(map[string]interface{})
	if !ok {
		return nil, errors.New("unexpected response: missing attributes field")
	}
	attributes["timestamp"] = float64(time.Now().Unix())
	// fmt.Printf("DEBUG VT (%s):\n%+v\n\n", endpointName, attributes)
	return attributes, nil
}

// QueryVTIP queries VirusTotal for an IP address.
func QueryVTIP(ctx context.Context, ip, apiKey string, maxRetries int) (map[string]interface{}, error) {
	endpoint := fmt.Sprintf(VTIPURL, ip)
	return queryVT(ctx, endpoint, apiKey, maxRetries, "VT IP")
}

// QueryVTFile queries VirusTotal for a file hash.
func QueryVTFile(ctx context.Context, hash, apiKey string, maxRetries int) (map[string]interface{}, error) {
	endpoint := fmt.Sprintf(VTFileURL, hash)
	return queryVT(ctx, endpoint, apiKey, maxRetries, "VT File")
}

// QueryVTURL queries VirusTotal for a URL.
func QueryVTURL(ctx context.Context, urlStr, apiKey string, maxRetries int) (map[string]interface{}, error) {
	// VT requires the URL to be URL-safe base64 encoded without padding.
	encoded := base64.URLEncoding.EncodeToString([]byte(urlStr))
	encoded = strings.TrimRight(encoded, "=")
	endpoint := fmt.Sprintf(VTURLLookup, encoded)
	return queryVT(ctx, endpoint, apiKey, maxRetries, "VT URL")
}

// QueryVTDomain queries VirusTotal for a domain.
func QueryVTDomain(ctx context.Context, domain, apiKey string, maxRetries int) (map[string]interface{}, error) {
	endpoint := fmt.Sprintf(VTDomainURL, domain)
	return queryVT(ctx, endpoint, apiKey, maxRetries, "VT Domain")
}
