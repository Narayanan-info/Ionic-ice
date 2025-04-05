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

// ScanFeaturePolicy checks for Feature-Policy (Permissions-Policy) Missing vulnerabilities in the provided subdomains.
func ScanFeaturePolicy(subdomains []string) {
	// Display the name tag for the scan type with colors
	banner := color.New(color.FgCyan).SprintFunc()
	success := color.New(color.FgGreen).SprintFunc()
	errorMsg := color.New(color.FgRed).SprintFunc()

	fmt.Println(banner("==================================="))
	fmt.Println(success("   Feature-Policy (Permissions-Policy) Missing   "))
	fmt.Println(banner("==================================="))

	outputDir := "./output/feature_policy"
	err := os.MkdirAll(outputDir, os.ModePerm)
	if err != nil {
		fmt.Println(errorMsg("Error creating output directory:"), err)
		return
	}

	// Open a file to save the results
	resultsFile := filepath.Join(outputDir, "feature_policy_vulnerabilities.txt")
	results, err := os.OpenFile(resultsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(errorMsg("Error creating results file:"), err)
		return
	}
	defer results.Close()

	// Write the banner to the file
	bannerText := "===================================\n   Feature-Policy (Permissions-Policy) Missing   \n===================================\n\n"
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

		fmt.Printf(color.YellowString("Scanning %s for Feature-Policy vulnerabilities...\n"), baseURL)

		// Perform the HTTP request
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get(baseURL)
		if err != nil {
			fmt.Printf(errorMsg("Error accessing %s: %v\n"), baseURL, err)
			continue
		}
		defer resp.Body.Close()

		// Check for the Feature-Policy or Permissions-Policy header
		featurePolicyHeader := resp.Header.Get("Feature-Policy")
		permissionsPolicyHeader := resp.Header.Get("Permissions-Policy")
		if featurePolicyHeader == "" && permissionsPolicyHeader == "" {
			_, err := results.WriteString(fmt.Sprintf("Vulnerable URL: %s\n  Issue: Missing Feature-Policy or Permissions-Policy header\n=========================\n", baseURL))
			if err != nil {
				fmt.Printf(errorMsg("Error writing findings to results file: %v\n"), err)
			}
			fmt.Printf(color.RedString("Vulnerable: %s (Missing Feature-Policy or Permissions-Policy header)\n"), baseURL)
		} else {
			headerValue := featurePolicyHeader
			if headerValue == "" {
				headerValue = permissionsPolicyHeader
			}
			fmt.Printf(color.GreenString("Secure: %s (Policy header found: %s)\n"), baseURL, headerValue)
		}
	}

	fmt.Println(success("Feature-Policy scan completed. Results saved to:"), resultsFile)
}
