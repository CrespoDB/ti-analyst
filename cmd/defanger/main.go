package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/CrespoDB/TI-analyst/pkg/core"
	"github.com/CrespoDB/TI-analyst/pkg/core/defanging"
)

func main() {
	mode := flag.String("mode", "defang", "Operation mode: defang or refang")
	flag.Parse()

	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading stdin:", err)
		os.Exit(1)
	}

	text := string(input)
	var output string
	if *mode == "refang" {
		output = defanging.RefangText(text)
	} else {
		output = defanging.DefangText(text)
		// Extract IOCs and save the buffer.
		iocs := core.ExtractIOCs(text)
		if err := core.SaveBuffer(iocs); err != nil {
			fmt.Fprintln(os.Stderr, "Error saving IOC buffer:", err)
		}
	}

	fmt.Print(output)
}
