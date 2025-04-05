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

// ScanXFF checks for X-Forwarded-For (IP Spoofing) vulnerabilities in the provided subdomains.
func ScanXFF(subdomains []string) {
	// Display the name tag for the scan type with colors
	banner := color.New(color.FgCyan).SprintFunc()
	success := color.New(color.FgGreen).SprintFunc()
	errorMsg := color.New(color.FgRed).SprintFunc()

	fmt.Println(banner("==================================="))
	fmt.Println(success("   X-Forwarded-For (IP Spoofing)   "))
	fmt.Println(banner("==================================="))

	outputDir := "./output/xff"
	err := os.MkdirAll(outputDir, os.ModePerm)
	if err != nil {
		fmt.Println(errorMsg("Error creating output directory:"), err)
		return
	}

	// Define payloads for X-Forwarded-For testing
	payloads := []string{
		"127.0.0.1",      // Localhost
		"192.168.1.1",    // Internal IP
		"10.0.0.1",       // Internal IP
		"::1",            // IPv6 localhost
		"8.8.8.8",        // Public IP (Google DNS)
		"1.1.1.1",        // Public IP (Cloudflare DNS)
		"evil.com",       // Malicious domain
		"localhost",      // Localhost as a string
		"127.0.0.1:8080", // Localhost with port
		"192.168.1.1:80", // Internal IP with port
		"::1:443",        // IPv6 localhost with port
	}

	// Open a file to save the results
	resultsFile := filepath.Join(outputDir, "xff_vulnerabilities.txt")
	results, err := os.OpenFile(resultsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(errorMsg("Error creating results file:"), err)
		return
	}
	defer results.Close()

	// Write the banner to the file
	bannerText := "===================================\n   X-Forwarded-For (IP Spoofing)   \n===================================\n\n"
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

		fmt.Printf(color.YellowString("Scanning %s for X-Forwarded-For vulnerabilities...\n"), baseURL)

		// Collect findings for the subdomain
		var findings []string

		for _, payload := range payloads {
			// Create a custom HTTP request
			req, err := http.NewRequest("GET", baseURL, nil)
			if err != nil {
				fmt.Printf(errorMsg("Error creating request for %s: %v\n"), baseURL, err)
				continue
			}

			// Add the X-Forwarded-For header with the payload
			req.Header.Set("X-Forwarded-For", payload)

			// Perform the HTTP request
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				fmt.Printf(errorMsg("Error accessing %s with X-Forwarded-For %s: %v\n"), baseURL, payload, err)
				continue
			}
			defer resp.Body.Close()

			// Check for signs of X-Forwarded-For spoofing in the response
			if resp.StatusCode == http.StatusOK && strings.Contains(resp.Request.Header.Get("X-Forwarded-For"), payload) {
				findings = append(findings, fmt.Sprintf(
					"Vulnerable URL: %s\n  X-Forwarded-For: %s\n  Status Code: %d\n",
					baseURL, payload, resp.StatusCode,
				))
			}
		}

		// Write findings for the subdomain to the file
		if len(findings) > 0 {
			_, err := results.WriteString(fmt.Sprintf("Findings for %s:\n%s\n=========================\n", baseURL, strings.Join(findings, "\n")))
			if err != nil {
				fmt.Printf(errorMsg("Error writing findings to results file: %v\n"), err)
			}
		}
	}

	fmt.Println(success("X-Forwarded-For scan completed. Results saved to:"), resultsFile)
}
