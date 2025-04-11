package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// fetchWithRetries performs an HTTP GET with retry logic.
// It accepts a context for cancellation and deadlines.
func fetchWithRetries(ctx context.Context, url string, headers map[string]string, params map[string]string, maxRetries int, backoffFactor int) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	// Append query parameters to the URL if provided.
	if params != nil {
		q := "?"
		var parts []string
		for k, v := range params {
			parts = append(parts, fmt.Sprintf("%s=%s", k, v))
		}
		q += strings.Join(parts, "&")
		url += q
	}

	var resp *http.Response
	var err error
	for attempt := 0; attempt < maxRetries; attempt++ {
		// Create a new request with the provided context.
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		// Set the headers.
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		// Execute the request.
		resp, err = client.Do(req)
		if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return nil, err
			}
			return body, nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		// Sleep before the next retry attempt.
		time.Sleep(time.Duration(backoffFactor*(1<<attempt)) * time.Second)
	}
	if err == nil {
		err = errors.New("failed to fetch data after retries")
	}
	return nil, err
}

