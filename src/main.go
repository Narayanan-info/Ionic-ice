package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"go-vulnerability-scanner/src/scanner" // Import the scanner package
)

// ANSI color codes
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
)

// DisplayBanner is a placeholder for the ASCII banner display
func DisplayBanner() {
	fmt.Println(ColorCyan + "====================================" + ColorReset)
	fmt.Println(ColorGreen + "ionic-ice Vulnerability Scanner Tool" + ColorReset)
	fmt.Println(ColorCyan + "====================================" + ColorReset)
}

// DisplayHelp shows the help information
func DisplayHelp() {
	DisplayBanner()
	fmt.Println(ColorCyan + "Usage:" + ColorReset)
	fmt.Println("  ./ionic [options]")
	fmt.Println()
	fmt.Println(ColorYellow + "Options:" + ColorReset)
	fmt.Println("  -h, --help       Show this help message and exit")
	fmt.Println()
	fmt.Println("Steps:")
	fmt.Println("  1. Select the scan type")
	fmt.Println("  2. Provide the path to the subdomain list file.")
	fmt.Println("  3. The tool will scan for vulnerabilities and save results in the output directory.")
}

// ReadSubdomains reads a list of subdomains from a file
func ReadSubdomains(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var subdomains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			subdomains = append(subdomains, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return subdomains, nil
}

func main() {
	// Parse command-line flags
	helpFlag := flag.Bool("h", false, "Show help message")
	helpFlagLong := flag.Bool("help", false, "Show help message")
	flag.Parse()

	// Check if help flag is provided
	if *helpFlag || *helpFlagLong {
		DisplayHelp()
		return
	}

	// Display ASCII banner
	DisplayBanner()

	// Present scanning options
	fmt.Println(ColorYellow + "\nSelect scan type:\n" + ColorReset)
	fmt.Println(ColorBlue + "     1. CORS (Cross-Origin Resource Sharing)" + ColorReset)
	fmt.Println(ColorBlue + "     2. CRLF (Carriage Return and Line Feed)" + ColorReset)
	fmt.Println(ColorBlue + "     3. HHI (Host Header Injection)" + ColorReset)
	fmt.Println(ColorBlue + "     4. XFF (X-Forwarded-For IP Spoofing)" + ColorReset)
	fmt.Println(ColorBlue + "     5. Referer Header Manipulation" + ColorReset)
	fmt.Println(ColorBlue + "     6. Cache-Control & Pragma Bypass" + ColorReset)
	fmt.Println(ColorBlue + "     7. Content-Type Mismatch (XSS)" + ColorReset)
	fmt.Println(ColorBlue + "     8. Strict-Transport-Security (HSTS) Bypass" + ColorReset)
	fmt.Println(ColorBlue + "     9. X-XSS-Protection Disabled" + ColorReset)
	fmt.Println(ColorBlue + "    10. Content Security Policy (CSP) Bypass" + ColorReset)
	fmt.Println(ColorBlue + "    11. Server Header Leak (Info Disclosure)" + ColorReset)
	fmt.Println(ColorBlue + "    12. Cross-Origin-Opener-Policy (COOP) Bypass" + ColorReset)
	fmt.Println(ColorBlue + "    13. Cross-Origin-Resource-Policy (CORP) Missing" + ColorReset)
	fmt.Println(ColorBlue + "    14. X-Content-Type-Options Missing" + ColorReset)
	fmt.Println(ColorBlue + "    15. Feature-Policy (Permissions-Policy) Missing\n" + ColorReset)

	// Prompt user to select scan type
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(ColorCyan + "Select scan option: " + ColorReset)
	option, _ := reader.ReadString('\n')
	option = strings.TrimSpace(option)

	// Validate scan type
	if option != "1" && option != "2" && option != "3" && option != "4" && option != "5" && option != "6" && option != "7" && option != "8" && option != "9" && option != "10" && option != "11" && option != "12" && option != "13" && option != "14" && option != "15" {
		fmt.Println(ColorRed + "Invalid option selected. Please choose a valid scan type." + ColorReset)
		return
	}

	// Prompt user to enter the path to the subdomain list file
	fmt.Print(ColorCyan + "Enter the path to the subdomain list file: " + ColorReset)
	subdomainFilePath, _ := reader.ReadString('\n')
	subdomainFilePath = strings.TrimSpace(subdomainFilePath)

	// Validate subdomain file path
	if _, err := os.Stat(subdomainFilePath); os.IsNotExist(err) {
		fmt.Printf(ColorRed+"Error: File %s does not exist.\n"+ColorReset, subdomainFilePath)
		return
	}

	// Read subdomains from file
	subdomains, err := ReadSubdomains(subdomainFilePath)
	if err != nil {
		fmt.Printf(ColorRed+"Error reading subdomains: %v\n"+ColorReset, err)
		return
	}

	// Initiate scan based on user selection
	switch option {
	case "1":
		fmt.Println(ColorGreen + "\nStarting CORS scan..." + ColorReset)
		scanner.ScanCORS(subdomains)
	case "2":
		fmt.Println(ColorGreen + "\nStarting CRLF scan..." + ColorReset)
		scanner.ScanCRLF(subdomains)
	case "3":
		fmt.Println(ColorGreen + "\nStarting Host Header Injection scan..." + ColorReset)
		scanner.ScanHHI(subdomains)
	case "4":
		fmt.Println(ColorGreen + "\nStarting X-Forwarded-For scan..." + ColorReset)
		scanner.ScanXFF(subdomains)
	case "5":
		fmt.Println(ColorGreen + "\nStarting Referer Header Manipulation scan..." + ColorReset)
		scanner.ScanReferer(subdomains)
	case "6":
		fmt.Println(ColorGreen + "\nStarting Cache-Control & Pragma Bypass scan..." + ColorReset)
		scanner.ScanCacheControl(subdomains)
	case "7":
		fmt.Println(ColorGreen + "\nStarting Content-Type Mismatch (XSS) scan..." + ColorReset)
		scanner.ScanContentType(subdomains)
	case "8":
		fmt.Println(ColorGreen + "\nStarting Strict-Transport-Security (HSTS) Bypass scan..." + ColorReset)
		scanner.ScanHSTS(subdomains)
	case "9":
		fmt.Println(ColorGreen + "\nStarting X-XSS-Protection Disabled scan..." + ColorReset)
		scanner.ScanXXSSProtection(subdomains)
	case "10":
		fmt.Println(ColorGreen + "\nStarting Content Security Policy (CSP) Bypass scan..." + ColorReset)
		scanner.ScanCSP(subdomains)
	case "11":
		fmt.Println(ColorGreen + "\nStarting Server Header Leak (Info Disclosure) scan..." + ColorReset)
		scanner.ScanServerHeader(subdomains)
	case "12":
		fmt.Println(ColorGreen + "\nStarting Cross-Origin-Opener-Policy (COOP) Bypass scan..." + ColorReset)
		scanner.ScanCOOP(subdomains)
	case "13":
		fmt.Println(ColorGreen + "\nStarting Cross-Origin-Resource-Policy (CORP) Missing scan..." + ColorReset)
		scanner.ScanCORP(subdomains)
	case "14":
		fmt.Println(ColorGreen + "\nStarting X-Content-Type-Options Missing scan..." + ColorReset)
		scanner.ScanXContentTypeOptions(subdomains)
	case "15":
		fmt.Println(ColorGreen + "\nStarting Feature-Policy (Permissions-Policy) Missing scan..." + ColorReset)
		scanner.ScanFeaturePolicy(subdomains)
	}
}
