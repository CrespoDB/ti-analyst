package enrichment

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/CrespoDB/TI-analyst/pkg/core"
)

func EnrichIPs(ctx context.Context, ips []string, abuseipdbKey, vtKey string, maxRetries int) string {
	if len(ips) == 0 {
		return "[i] No IP addresses found."
	}

	var mu sync.Mutex
	var resultLines []string
	cache, _ := core.LoadCache()
	updated := false
	var wg sync.WaitGroup

	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			var sb strings.Builder
			sb.WriteString(ip + "\n")

			var abuseResult map[string]interface{}
			if entry, ok := cache[ip]; ok && !core.IsStale(entry, 24) {
				abuseResult = entry
			} else {
				time.Sleep(1 * time.Second)
				res, err := core.QueryAbuseIPDB(ctx, ip, abuseipdbKey, maxRetries)
				if err != nil {
					sb.WriteString(fmt.Sprintf("  AbuseIPDB error: %v\n", err))
				} else {
					abuseResult = res
					cache[ip] = abuseResult
					updated = true
				}
			}
			if abuseResult != nil {
				sb.WriteString("  AbuseIPDB:\n")
				sb.WriteString(fmt.Sprintf("    Score           : %v\n", abuseResult["abuseConfidenceScore"]))
				sb.WriteString(fmt.Sprintf("    Country         : %v\n", abuseResult["countryCode"]))
				sb.WriteString(fmt.Sprintf("    Domain          : %v\n", abuseResult["domain"]))

				if hostnames, ok := abuseResult["hostnames"].([]interface{}); ok && len(hostnames) > 0 {
					sb.WriteString(fmt.Sprintf("    Hostnames       : %v\n", hostnames[0]))
				}

				sb.WriteString(fmt.Sprintf("    ISP             : %v\n", abuseResult["isp"]))
				sb.WriteString(fmt.Sprintf("    Usage Type      : %v\n", abuseResult["usageType"]))
				sb.WriteString(fmt.Sprintf("    Total Reports   : %v\n", abuseResult["totalReports"]))
				sb.WriteString(fmt.Sprintf("    Distinct Users  : %v\n", abuseResult["numDistinctUsers"]))
				sb.WriteString(fmt.Sprintf("    Last Reported   : %v\n", abuseResult["lastReportedAt"]))
			}

			time.Sleep(1 * time.Second)
			vtResult, err := core.QueryVTIP(ctx, ip, vtKey, maxRetries)
			if err != nil {
				sb.WriteString(fmt.Sprintf("  VT error: %v\n", err))
			} else {
				stats, _ := vtResult["last_analysis_stats"].(map[string]interface{})
				sb.WriteString("  VT:\n")
				sb.WriteString(fmt.Sprintf("    VT Verdict       : %v/%v\n", stats["malicious"], stats["harmless"]))
				sb.WriteString(fmt.Sprintf("    Reverse DNS      : %v\n", vtResult["reverse_dns"]))
				sb.WriteString(fmt.Sprintf("    WHOIS Org        : %v\n", vtResult["whois_org"]))

			}

			mu.Lock()
			resultLines = append(resultLines, sb.String())
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	if updated {
		core.SaveCache(cache)
	}
	return strings.Join(resultLines, "\n")
}

func EnrichHashes(ctx context.Context, hashes []string, vtKey string, maxRetries int) string {
	if len(hashes) == 0 {
		return "[i] No hashes found."
	}

	var mu sync.Mutex
	var resultLines []string
	var wg sync.WaitGroup

	for _, hash := range hashes {
		wg.Add(1)
		go func(hash string) {
			defer wg.Done()
			var sb strings.Builder
			sb.WriteString(hash + "\n")

			time.Sleep(1 * time.Second)
			result, err := core.QueryVTFile(ctx, hash, vtKey, maxRetries)
			if err != nil {
				sb.WriteString(fmt.Sprintf("  VT error: %v\n", err))
			} else {
				stats, _ := result["last_analysis_stats"].(map[string]interface{})
				ts := formatTimestamp(result["last_analysis_date"])

				var name string
				if names, ok := result["names"].([]interface{}); ok && len(names) > 0 {
					name = fmt.Sprintf("%v", names[0])
				}

				sb.WriteString("  VT:\n")
				sb.WriteString(fmt.Sprintf("    Last Seen       : %v\n", ts))
				sb.WriteString(fmt.Sprintf("    VT Verdict       : %v/%v\n", stats["malicious"], stats["harmless"]))
				sb.WriteString(fmt.Sprintf("    Known Filename   : %v\n", name))
				sb.WriteString(fmt.Sprintf("    First Seen       : %v\n", formatTimestamp(result["first_submission_date"])))
				sb.WriteString(fmt.Sprintf("    Tags             : %v\n", result["tags"]))

			}

			mu.Lock()
			resultLines = append(resultLines, sb.String())
			mu.Unlock()
		}(hash)
	}
	wg.Wait()
	return strings.Join(resultLines, "\n")
}

func EnrichURLs(ctx context.Context, urls []string, vtKey string, maxRetries int) string {
	if len(urls) == 0 {
		return "[i] No URLs found."
	}

	var mu sync.Mutex
	var resultLines []string
	var wg sync.WaitGroup

	for _, urlStr := range urls {
		wg.Add(1)
		go func(urlStr string) {
			defer wg.Done()
			var sb strings.Builder
			sb.WriteString(urlStr + "\n")

			time.Sleep(1 * time.Second)
			result, err := core.QueryVTURL(ctx, urlStr, vtKey, maxRetries)
			if err != nil {
				sb.WriteString(fmt.Sprintf("  VT error: %v\n", err))
			} else {
				stats, _ := result["last_analysis_stats"].(map[string]interface{})
				sb.WriteString("  VT:\n")
				sb.WriteString(fmt.Sprintf("    VT Verdict       : %v/%v\n", stats["malicious"], stats["harmless"]))
				sb.WriteString(fmt.Sprintf("    Redirect Chain   : %v\n", result["redirect_chain"]))
				sb.WriteString(fmt.Sprintf("    Final Landing Page : %v\n", result["final_url"]))
				sb.WriteString(fmt.Sprintf("    URL Scan Tags    : %v\n", result["tags"]))
				sb.WriteString(fmt.Sprintf("    Host Reputation  : %v\n", result["reputation"]))

			}

			mu.Lock()
			resultLines = append(resultLines, sb.String())
			mu.Unlock()
		}(urlStr)
	}
	wg.Wait()
	return strings.Join(resultLines, "\n")
}

func EnrichDomains(ctx context.Context, domains []string, vtKey string, maxRetries int) string {
	if len(domains) == 0 {
		return "[i] No domains found."
	}

	var mu sync.Mutex
	var resultLines []string
	var wg sync.WaitGroup

	for _, domain := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			var sb strings.Builder
			sb.WriteString(domain + "\n")

			time.Sleep(1 * time.Second)
			result, err := core.QueryVTDomain(ctx, domain, vtKey, maxRetries)
			if err != nil {
				sb.WriteString(fmt.Sprintf("  VT error: %v\n", err))
			} else {
				stats, _ := result["last_analysis_stats"].(map[string]interface{})
				sb.WriteString("  VT:\n")
				sb.WriteString(fmt.Sprintf("    VT Verdict       : %v/%v\n", stats["malicious"], stats["harmless"]))
				sb.WriteString(fmt.Sprintf("    Categories       : %v\n", result["categories"]))
				sb.WriteString(fmt.Sprintf("    Registrar        : %v\n", result["registrar"]))
				sb.WriteString(fmt.Sprintf("    Created          : %v\n", result["creation_date"]))
				sb.WriteString(fmt.Sprintf("    Expires          : %v\n", result["expiration_date"]))
				sb.WriteString(fmt.Sprintf("    Registered Country : %v\n", result["registrant_country"]))
				sb.WriteString(fmt.Sprintf("    Subdomains       : %v\n", result["subdomains"]))
				sb.WriteString(fmt.Sprintf("    Hosting IP       : %v\n", result["resolutions"]))

			}

			mu.Lock()
			resultLines = append(resultLines, sb.String())
			mu.Unlock()
		}(domain)
	}
	wg.Wait()
	return strings.Join(resultLines, "\n")
}

func EnrichText(ctx context.Context, content, abuseipdbKey, vtKey string, maxRetries int) string {
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
		resultsChan <- EnrichIPs(ctx, ips, abuseipdbKey, vtKey, maxRetries)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		resultsChan <- EnrichHashes(ctx, hashes, vtKey, maxRetries)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		resultsChan <- EnrichURLs(ctx, urls, vtKey, maxRetries)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		resultsChan <- EnrichDomains(ctx, domains, vtKey, maxRetries)
	}()
	wg.Wait()
	close(resultsChan)

	var finalResults []string
	for r := range resultsChan {
		if r != "" {
			finalResults = append(finalResults, r)
		}
	}
	if len(finalResults) == 0 {
		return "[i] No IOCs enriched."
	}
	return strings.Join(finalResults, "\n\n")
}

// formatTimestamp converts Unix float to readable date (optional)
func formatTimestamp(val interface{}) string {
	if v, ok := val.(float64); ok {
		return time.Unix(int64(v), 0).Format("2006-01-02")
	}
	return "n/a"
}

