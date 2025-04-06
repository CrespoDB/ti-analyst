package core

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// fetchWithRetries performs an HTTP GET with retry logic.
func fetchWithRetries(url string, headers map[string]string, params map[string]string, maxRetries int, backoffFactor int) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}
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
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
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
		time.Sleep(time.Duration(backoffFactor*(1<<attempt)) * time.Second)
	}
	if err == nil {
		err = errors.New("failed to fetch data after retries")
	}
	return nil, err
}
