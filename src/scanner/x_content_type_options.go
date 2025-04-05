package scanner

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
)

// ScanXContentTypeOptions checks for X-Content-Type-Options Missing vulnerabilities in the provided subdomains.
func ScanXContentTypeOptions(subdomains []string) {
	// Display the name tag for the scan type with colors
	banner := color.New(color.FgCyan).SprintFunc()
	success := color.New(color.FgGreen).SprintFunc()
	errorMsg := color.New(color.FgRed).SprintFunc()

	fmt.Println(banner("==================================="))
	fmt.Println(success("   X-Content-Type-Options Missing   "))
	fmt.Println(banner("==================================="))

	outputDir := "./output/x_content_type_options"
	err := os.MkdirAll(outputDir, os.ModePerm)
	if err != nil {
		fmt.Println(errorMsg("Error creating output directory:"), err)
		return
	}

	// Open a file to save the results
	resultsFile := filepath.Join(outputDir, "x_content_type_options_vulnerabilities.txt")
	results, err := os.OpenFile(resultsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(errorMsg("Error creating results file:"), err)
		return
	}
	defer results.Close()

	// Write the banner to the file
	bannerText := "===================================\n   X-Content-Type-Options Missing   \n===================================\n\n"
	_, err = results.WriteString(bannerText)
	if err != nil {
		fmt.Printf(errorMsg("Error writing banner to results file: %v\n"), err)
		return
	}

	// Iterate over each subdomain
	for _, subdomain := range subdomains {
		// Ensure the URL has a valid scheme
		var baseURL string
		if strings.HasPrefix(subdomain, "http://") || strings.HasPrefix(subdomain, "https://") {
			baseURL = subdomain
		} else {
			baseURL = fmt.Sprintf("http://%s", subdomain)
		}

		fmt.Printf(color.YellowString("Scanning %s for X-Content-Type-Options vulnerabilities...\n"), baseURL)

		// Perform the HTTP request
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get(baseURL)
		if err != nil {
			fmt.Printf(errorMsg("Error accessing %s: %v\n"), baseURL, err)
			continue
		}
		defer resp.Body.Close()

		// Check for the X-Content-Type-Options header
		xContentTypeOptionsHeader := resp.Header.Get("X-Content-Type-Options")
		if xContentTypeOptionsHeader == "" {
			_, err := results.WriteString(fmt.Sprintf("Vulnerable URL: %s\n  Issue: Missing X-Content-Type-Options header\n=========================\n", baseURL))
			if err != nil {
				fmt.Printf(errorMsg("Error writing findings to results file: %v\n"), err)
			}
			fmt.Printf(color.RedString("Vulnerable: %s (Missing X-Content-Type-Options header)\n"), baseURL)
		} else if strings.ToLower(xContentTypeOptionsHeader) != "nosniff" {
			_, err := results.WriteString(fmt.Sprintf("Vulnerable URL: %s\n  Issue: Weak X-Content-Type-Options header (Value: %s)\n=========================\n", baseURL, xContentTypeOptionsHeader))
			if err != nil {
				fmt.Printf(errorMsg("Error writing findings to results file: %v\n"), err)
			}
			fmt.Printf(color.RedString("Vulnerable: %s (Weak X-Content-Type-Options header: %s)\n"), baseURL, xContentTypeOptionsHeader)
		} else {
			fmt.Printf(color.GreenString("Secure: %s (X-Content-Type-Options header found: %s)\n"), baseURL, xContentTypeOptionsHeader)
		}
	}

	fmt.Println(success("X-Content-Type-Options scan completed. Results saved to:"), resultsFile)
}
