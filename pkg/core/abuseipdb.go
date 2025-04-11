package core

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// AbuseIPDBURL is the endpoint for AbuseIPDB queries.
const AbuseIPDBURL = "https://api.abuseipdb.com/api/v2/check"

// QueryAbuseIPDB queries AbuseIPDB for a given IP address.
// It accepts context to allow cancellation and deadlines.
func QueryAbuseIPDB(ctx context.Context, ip, apiKey string, maxRetries int) (map[string]interface{}, error) {
	headers := map[string]string{
		"Key":    apiKey,
		"Accept": "application/json",
	}
	params := map[string]string{
		"ipAddress":    ip,
		"maxAgeInDays": "90",
	}
	body, err := fetchWithRetries(ctx, AbuseIPDBURL, headers, params, maxRetries, 1)
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

