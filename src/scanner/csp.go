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

// ScanCSP checks for Content Security Policy (CSP) Bypass vulnerabilities in the provided subdomains.
func ScanCSP(subdomains []string) {
	// Display the name tag for the scan type with colors
	banner := color.New(color.FgCyan).SprintFunc()
	success := color.New(color.FgGreen).SprintFunc()
	errorMsg := color.New(color.FgRed).SprintFunc()

	fmt.Println(banner("==================================="))
	fmt.Println(success("   Content Security Policy (CSP) Bypass   "))
	fmt.Println(banner("==================================="))

	outputDir := "./output/csp"
	err := os.MkdirAll(outputDir, os.ModePerm)
	if err != nil {
		fmt.Println(errorMsg("Error creating output directory:"), err)
		return
	}

	// Open a file to save the results
	resultsFile := filepath.Join(outputDir, "csp_vulnerabilities.txt")
	results, err := os.OpenFile(resultsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(errorMsg("Error creating results file:"), err)
		return
	}
	defer results.Close()

	// Write the banner to the file
	bannerText := "===================================\n   Content Security Policy (CSP) Bypass   \n===================================\n\n"
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

		fmt.Printf(color.YellowString("Scanning %s for CSP vulnerabilities...\n"), baseURL)

		// Perform the HTTP request
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get(baseURL)
		if err != nil {
			fmt.Printf(errorMsg("Error accessing %s: %v\n"), baseURL, err)
			continue
		}
		defer resp.Body.Close()

		// Check for the Content-Security-Policy header
		cspHeader := resp.Header.Get("Content-Security-Policy")
		if cspHeader == "" {
			_, err := results.WriteString(fmt.Sprintf("Vulnerable URL: %s\n  Issue: Missing Content-Security-Policy header\n=========================\n", baseURL))
			if err != nil {
				fmt.Printf(errorMsg("Error writing findings to results file: %v\n"), err)
			}
			fmt.Printf(color.RedString("Vulnerable: %s (Missing Content-Security-Policy header)\n"), baseURL)
		} else if strings.Contains(cspHeader, "'unsafe-inline'") || strings.Contains(cspHeader, "https://evil.com") {
			_, err := results.WriteString(fmt.Sprintf("Vulnerable URL: %s\n  Issue: Weak CSP configuration (Header: %s)\n=========================\n", baseURL, cspHeader))
			if err != nil {
				fmt.Printf(errorMsg("Error writing findings to results file: %v\n"), err)
			}
			fmt.Printf(color.RedString("Vulnerable: %s (Weak CSP configuration: %s)\n"), baseURL, cspHeader)
		} else {
			fmt.Printf(color.GreenString("Secure: %s (CSP header found: %s)\n"), baseURL, cspHeader)
		}
	}

	fmt.Println(success("CSP scan completed. Results saved to:"), resultsFile)
}
