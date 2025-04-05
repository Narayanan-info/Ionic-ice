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

// ScanXXSSProtection checks for X-XSS-Protection Disabled vulnerabilities in the provided subdomains.
func ScanXXSSProtection(subdomains []string) {
	// Display the name tag for the scan type with colors
	banner := color.New(color.FgCyan).SprintFunc()
	success := color.New(color.FgGreen).SprintFunc()
	errorMsg := color.New(color.FgRed).SprintFunc()

	fmt.Println(banner("==================================="))
	fmt.Println(success("   X-XSS-Protection Disabled Scan   "))
	fmt.Println(banner("==================================="))

	outputDir := "./output/x_xss_protection"
	err := os.MkdirAll(outputDir, os.ModePerm)
	if err != nil {
		fmt.Println(errorMsg("Error creating output directory:"), err)
		return
	}

	// Open a file to save the results
	resultsFile := filepath.Join(outputDir, "x_xss_protection_vulnerabilities.txt")
	results, err := os.OpenFile(resultsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(errorMsg("Error creating results file:"), err)
		return
	}
	defer results.Close()

	// Write the banner to the file
	bannerText := "===================================\n   X-XSS-Protection Disabled Scan   \n===================================\n\n"
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

		fmt.Printf(color.YellowString("Scanning %s for X-XSS-Protection vulnerabilities...\n"), baseURL)

		// Perform the HTTP request
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get(baseURL)
		if err != nil {
			fmt.Printf(errorMsg("Error accessing %s: %v\n"), baseURL, err)
			continue
		}
		defer resp.Body.Close()

		// Check for the X-XSS-Protection header
		xssProtectionHeader := resp.Header.Get("X-XSS-Protection")
		if xssProtectionHeader == "" || xssProtectionHeader == "0" {
			_, err := results.WriteString(fmt.Sprintf("Vulnerable URL: %s\n  Issue: Missing or disabled X-XSS-Protection header (Value: %s)\n=========================\n", baseURL, xssProtectionHeader))
			if err != nil {
				fmt.Printf(errorMsg("Error writing findings to results file: %v\n"), err)
			}
			fmt.Printf(color.RedString("Vulnerable: %s (X-XSS-Protection header missing or disabled: %s)\n"), baseURL, xssProtectionHeader)
		} else {
			fmt.Printf(color.GreenString("Secure: %s (X-XSS-Protection header found: %s)\n"), baseURL, xssProtectionHeader)
		}
	}

	fmt.Println(success("X-XSS-Protection scan completed. Results saved to:"), resultsFile)
}
