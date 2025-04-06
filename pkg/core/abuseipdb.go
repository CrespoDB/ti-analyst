package core

import (
	"encoding/json"
	"errors"
	"time"
)

// AbuseIPDBURL constant is defined in enrichment package or here.
// If defined elsewhere, adjust the import accordingly.
const AbuseIPDBURL = "https://api.abuseipdb.com/api/v2/check"

// QueryAbuseIPDB queries AbuseIPDB for a given IP.
func QueryAbuseIPDB(ip, apiKey string, maxRetries int) (map[string]interface{}, error) {
	headers := map[string]string{
		"Key":    apiKey,
		"Accept": "application/json",
	}
	params := map[string]string{
		"ipAddress":    ip,
		"maxAgeInDays": "90",
	}
	body, err := fetchWithRetries(AbuseIPDBURL, headers, params, maxRetries, 1)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	if data, ok := result["data"].(map[string]interface{}); ok {
		data["timestamp"] = float64(time.Now().Unix())
		return data, nil
	}
	return nil, errors.New("unexpected response from AbuseIPDB")
}
