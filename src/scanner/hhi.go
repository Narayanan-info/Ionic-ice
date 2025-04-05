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

// ScanHHI checks for Host Header Injection vulnerabilities in the provided subdomains.
func ScanHHI(subdomains []string) {
	// Display the name tag for the scan type with colors
	banner := color.New(color.FgCyan).SprintFunc()
	success := color.New(color.FgGreen).SprintFunc()
	errorMsg := color.New(color.FgRed).SprintFunc()

	fmt.Println(banner("==================================="))
	fmt.Println(success("    Host Header Injection Scan   "))
	fmt.Println(banner("==================================="))

	outputDir := "./output/hhi"
	err := os.MkdirAll(outputDir, os.ModePerm)
	if err != nil {
		fmt.Println(errorMsg("Error creating output directory:"), err)
		return
	}

	// Define enhanced payloads for Host Header Injection testing
	payloads := []string{
		"evil.com",                      // Malicious domain
		"127.0.0.1",                     // Localhost
		"localhost",                     // Localhost
		"example.com",                   // Trusted domain
		"www.google.com",                // Common domain
		"",                              // Empty Host header
		" ",                             // Space as Host header
		"\r\nInjected-Header: test",     // Header injection attempt
		"evil.com\r\nX-Injected: 1",     // Inject custom header
		"127.0.0.1:80",                  // Localhost with port
		"localhost:8080",                // Localhost with custom port
		"evil.com:443",                  // Malicious domain with HTTPS port
		"::1",                           // IPv6 localhost
		"[::1]:80",                      // IPv6 localhost with port
		"10.0.0.1",                      // Internal IP
		"192.168.1.1",                   // Internal IP
		"evil.com\r\nContent-Length: 0", // Inject Content-Length header
	}

	// Open a file to save the results
	resultsFile := filepath.Join(outputDir, "hhi_vulnerabilities.txt")
	results, err := os.OpenFile(resultsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(errorMsg("Error creating results file:"), err)
		return
	}
	defer results.Close()

	// Write the banner to the file
	bannerText := "===================================\n      Host Header Injection Scan   \n===================================\n\n"
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

		fmt.Printf(color.YellowString("Scanning %s for Host Header Injection vulnerabilities...\n"), baseURL)

		// Collect findings for the subdomain
		var findings []string

		for _, payload := range payloads {
			// Create a custom HTTP request
			req, err := http.NewRequest("GET", baseURL, nil)
			if err != nil {
				fmt.Printf(errorMsg("Error creating request for %s: %v\n"), baseURL, err)
				continue
			}

			// Add the Host header with the payload
			req.Header.Set("Host", payload)

			// Perform the HTTP request
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				fmt.Printf(errorMsg("Error accessing %s with Host header %s: %v\n"), baseURL, payload, err)
				continue
			}
			defer resp.Body.Close()

			// Check for signs of Host Header Injection in the response
			if resp.StatusCode == http.StatusOK && strings.Contains(resp.Request.Host, payload) {
				findings = append(findings, fmt.Sprintf(
					"Vulnerable URL: %s\n  Host Header: %s\n  Status Code: %d\n",
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

	fmt.Println(success("Host Header Injection scan completed. Results saved to:"), resultsFile)
}
