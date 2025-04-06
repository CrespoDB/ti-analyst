package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/CrespoDB/TI-analyst/pkg/core/enrichment"
)

func main() {
	maxRetries := flag.Int("max-retries", 3, "Max retry attempts")
	filePath := flag.String("file", "", "File to read (default: stdin)")
	flag.Parse()

	abuseipdbKey := os.Getenv("ABUSEIPDB_KEY")
	vtKey := os.Getenv("VT_KEY")
	if abuseipdbKey == "" {
		fmt.Fprintln(os.Stderr, "[!] ABUSEIPDB_KEY env var missing")
		os.Exit(1)
	}
	if vtKey == "" {
		fmt.Fprintln(os.Stderr, "[!] VT_KEY env var missing")
		os.Exit(1)
	}

	var content string
	if *filePath != "" {
		data, err := os.ReadFile(*filePath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error reading file:", err)
			os.Exit(1)
		}
		content = string(data)
	} else {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error reading stdin:", err)
			os.Exit(1)
		}
		content = string(data)
	}

	result := enrichment.EnrichText(content, abuseipdbKey, vtKey, *maxRetries)
	fmt.Print(result)
}
