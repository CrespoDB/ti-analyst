package enrichment

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/CrespoDB/TI-analyst/pkg/core"
)

// EnrichIPs concurrently enriches a list of IP addresses.
func EnrichIPs(ips []string, abuseipdbKey, vtKey string, maxRetries int) string {
	if len(ips) == 0 {
		return "[i] No IP addresses found."
	}
	var mu sync.Mutex
	var resultLines []string
	resultLines = append(resultLines, fmt.Sprintf("[+] Found %d IP(s). Querying AbuseIPDB and VirusTotal...\n", len(ips)))
	cache, _ := core.LoadCache()
	updated := false
	var wg sync.WaitGroup
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			var sb strings.Builder
			var abuseResult map[string]interface{}
			if entry, ok := cache[ip]; ok && !core.IsStale(entry, 24) {
				abuseResult = entry
			} else {
				time.Sleep(1 * time.Second)
				res, err := core.QueryAbuseIPDB(ip, abuseipdbKey, maxRetries)
				if err != nil {
					sb.WriteString(fmt.Sprintf("  AbuseIPDB Error: %v\n", err))
				} else {
					abuseResult = res
					sb.WriteString(fmt.Sprintf("  AbuseIPDB:\n    Score       : %v\n    Country     : %v\n    ISP         : %v\n    Reports     : %v\n    Last Seen   : %v\n",
						abuseResult["abuseConfidenceScore"],
						abuseResult["countryCode"],
						abuseResult["isp"],
						abuseResult["totalReports"],
						abuseResult["lastReportedAt"],
					))
					cache[ip] = abuseResult
					updated = true
				}
			}
			time.Sleep(1 * time.Second)
			vtResult, err := core.QueryVTIP(ip, vtKey, maxRetries)
			if err != nil {
				sb.WriteString(fmt.Sprintf("  VirusTotal IP Error: %v\n", err))
			} else {
				sb.WriteString(fmt.Sprintf("  VirusTotal:\n    Country     : %v\n    ASN         : %v\n    Network     : %v\n    Analysis    : %v\n",
					vtResult["country"],
					vtResult["asn"],
					vtResult["network"],
					vtResult["last_analysis_stats"],
				))
			}
			mu.Lock()
			resultLines = append(resultLines, ip+":\n"+sb.String()+"\n")
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	if updated {
		core.SaveCache(cache)
	}
	return strings.Join(resultLines, "\n")
}

// EnrichHashes concurrently enriches a list of file hashes.
func EnrichHashes(hashes []string, vtKey string, maxRetries int) string {
	if len(hashes) == 0 {
		return "[i] No hashes found."
	}
	var mu sync.Mutex
	var resultLines []string
	resultLines = append(resultLines, fmt.Sprintf("[+] Found %d hash(es). Querying VirusTotal...\n", len(hashes)))
	var wg sync.WaitGroup
	for _, hash := range hashes {
		wg.Add(1)
		go func(hash string) {
			defer wg.Done()
			var sb strings.Builder
			time.Sleep(1 * time.Second)
			result, err := core.QueryVTFile(hash, vtKey, maxRetries)
			if err != nil {
				sb.WriteString(fmt.Sprintf("  VirusTotal File Error: %v\n", err))
			} else {
				// Extract file name from "names" if available
				var fileName string
				if names, ok := result["names"].([]interface{}); ok && len(names) > 0 {
					fileName = fmt.Sprintf("%v", names[0])
				}
				fileType := result["type_description"]
				lastAnalysisDate := result["last_analysis_date"]
				analysisStats := result["last_analysis_stats"]

				// Extract malicious vendors from last_analysis_results.
				maliciousVendors := []string{}
				if resultsMap, ok := result["last_analysis_results"].(map[string]interface{}); ok {
					for vendor, info := range resultsMap {
						if infoMap, ok := info.(map[string]interface{}); ok {
							if category, ok := infoMap["category"].(string); ok && category == "malicious" {
								maliciousVendors = append(maliciousVendors, vendor)
							}
						}
					}
				}

				sb.WriteString("  VirusTotal Response:\n")
				sb.WriteString(fmt.Sprintf("    File Name         : %v\n", fileName))
				sb.WriteString(fmt.Sprintf("    Type              : %v\n", fileType))
				sb.WriteString(fmt.Sprintf("    Last Analysis Date: %v\n", lastAnalysisDate))
				sb.WriteString(fmt.Sprintf("    Analysis Stats    : %v\n", analysisStats))
				sb.WriteString(fmt.Sprintf("    Malicious Vendors : %v\n", maliciousVendors))
			}
			mu.Lock()
			resultLines = append(resultLines, hash+":\n"+sb.String()+"\n")
			mu.Unlock()
		}(hash)
	}
	wg.Wait()
	return strings.Join(resultLines, "\n")
}

// EnrichURLs concurrently enriches a list of URLs.
func EnrichURLs(urls []string, vtKey string, maxRetries int) string {
	if len(urls) == 0 {
		return "[i] No URLs found."
	}
	var mu sync.Mutex
	var resultLines []string
	resultLines = append(resultLines, fmt.Sprintf("[+] Found %d URL(s). Querying VirusTotal...\n", len(urls)))
	var wg sync.WaitGroup
	for _, urlStr := range urls {
		wg.Add(1)
		go func(urlStr string) {
			defer wg.Done()
			var sb strings.Builder
			time.Sleep(1 * time.Second)
			result, err := core.QueryVTURL(urlStr, vtKey, maxRetries)
			if err != nil {
				sb.WriteString(fmt.Sprintf("  VirusTotal URL Error: %v\n", err))
			} else {
				sb.WriteString(fmt.Sprintf("  VirusTotal:\n    Category    : %v\n    Malicious   : %v\n",
					result["category"],
					result["malicious_votes"],
				))
			}
			mu.Lock()
			resultLines = append(resultLines, urlStr+":\n"+sb.String()+"\n")
			mu.Unlock()
		}(urlStr)
	}
	wg.Wait()
	return strings.Join(resultLines, "\n")
}

// EnrichDomains concurrently enriches a list of domains.
func EnrichDomains(domains []string, vtKey string, maxRetries int) string {
	if len(domains) == 0 {
		return "[i] No domains found."
	}
	var mu sync.Mutex
	var resultLines []string
	resultLines = append(resultLines, fmt.Sprintf("[+] Found %d domain(s). Querying VirusTotal...\n", len(domains)))
	var wg sync.WaitGroup
	for _, domain := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			var sb strings.Builder
			time.Sleep(1 * time.Second)
			result, err := core.QueryVTDomain(domain, vtKey, maxRetries)
			if err != nil {
				sb.WriteString(fmt.Sprintf("  VirusTotal Domain Error: %v\n", err))
			} else {
				sb.WriteString(fmt.Sprintf("  VirusTotal:\n    Reputation  : %v\n    Analysis    : %v\n",
					result["reputation"],
					result["last_analysis"],
				))
			}
			mu.Lock()
			resultLines = append(resultLines, domain+":\n"+sb.String()+"\n")
			mu.Unlock()
		}(domain)
	}
	wg.Wait()
	return strings.Join(resultLines, "\n")
}

// EnrichText extracts IOCs from content, saves the IOC buffer,
// and runs enrichment functions concurrently for IPs, hashes, URLs, and domains.
func EnrichText(content, abuseipdbKey, vtKey string, maxRetries int) string {
	iocs := core.ExtractIOCs(content)
	core.SaveBuffer(iocs)
	var ips, hashes, urls, domains []string
	for _, ioc := range iocs {
		switch ioc.Type {
		case "ip":
			ips = append(ips, ioc.Value)
		case "hash":
			hashes = append(hashes, ioc.Value)
		case "url":
			urls = append(urls, ioc.Value)
		case "domain":
			domains = append(domains, ioc.Value)
		}
	}
	var wg sync.WaitGroup
	resultsChan := make(chan string, 4)
	wg.Add(1)
	go func() {
		defer wg.Done()
		resultsChan <- EnrichIPs(ips, abuseipdbKey, vtKey, maxRetries)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		resultsChan <- EnrichHashes(hashes, vtKey, maxRetries)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		resultsChan <- EnrichURLs(urls, vtKey, maxRetries)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		resultsChan <- EnrichDomains(domains, vtKey, maxRetries)
	}()
	wg.Wait()
	close(resultsChan)
	var finalResults []string
	for r := range resultsChan {
		finalResults = append(finalResults, r)
	}
	return strings.Join(finalResults, "\n\n")
}
