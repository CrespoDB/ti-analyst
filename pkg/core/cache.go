package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// CacheEntry is a map for caching enrichment results.
type CacheEntry map[string]interface{}

// LoadCache reads the cache file (if it exists) and unmarshals JSON.
func LoadCache() (map[string]CacheEntry, error) {
	cachePath := filepath.Join(filepath.Dir(BufferFile), "ioc_enrichment_cache.json")
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return make(map[string]CacheEntry), nil
	}
	var cache map[string]CacheEntry
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, err
	}
	return cache, nil
}

// SaveCache writes the cache map as JSON to a file.
func SaveCache(cache map[string]CacheEntry) error {
	cachePath := filepath.Join(filepath.Dir(BufferFile), "ioc_enrichment_cache.json")
	dir := filepath.Dir(cachePath)
	os.MkdirAll(dir, 0755)
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cachePath, data, 0644)
}

// IsStale checks if a cache entry is older than maxAgeHours.
func IsStale(entry CacheEntry, maxAgeHours int) bool {
	ts, ok := entry["timestamp"].(float64)
	if !ok {
		return true
	}
	elapsed := time.Since(time.Unix(int64(ts), 0))
	return elapsed > time.Duration(maxAgeHours)*time.Hour
}
