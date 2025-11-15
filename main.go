package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
)

// Predefined dorks
// Predefined dorks
// Predefined dorks
// Predefined dorks
// Predefined dorks
var predefinedDorks = []Dork{
	// the first part will bo shown in choice and the second part will be use on the querry

	{"ssl.cert.subject.CN:\"example.com\" 200", "ssl.cert.subject.CN:\"%s\""},
	{"hostname:\"example.com\" 200", "hostname:\"%s\""},
	{"ssl:\"example.com\" 200", "ssl:\"%s\""},
	// Add more predefined dorks as needed
}

// Add more predefined dorks as needed
// Add more predefined dorks as needed
// Add more predefined dorks as needed
// Add more predefined dorks as needed
// Add more predefined dorks as needed

const (
	reset = "\033[0m"
	green = "\033[32m"
)

const shodanURL = "https://api.shodan.io/dns/domain/"
const shodanBaseURL = "https://api.shodan.io/shodan/host/search"

var uniqueMap = make(map[string]bool)

type ShodanResponse struct {
	Matches []struct {
		IPString string   `json:"ip_str"`
		Hostnames []string `json:"hostnames"`
	} `json:"matches"`
}

type SubdomainResponse struct {
	Domain     string      `json:"domain,omitempty"`
	Tags       []string    `json:"tags,omitempty"`
	Data       []Subdomain `json:"data,omitempty"`
	SubDomains []string    `json:"subdomains,omitempty"`
}

type Subdomain struct {
	SubD     string `json:"subdomain,omitempty"`
	Type     string `json:"type,omitempty"`
	Value    string `json:"value,omitempty"`
	LastSeen string `json:"last_seen,omitempty"`
}

type Dork struct {
	Description string
	Query       string
}

const argusLogo = `
  █▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█  
  █                                                █
  █    █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗   █
  █   ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝   █
  █   ███████║██████╔╝██║  ███╗██║   ██║███████╗   █
  █   ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║   █
  █   ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║   █
  █   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝   █
  █                                     v1.1       █
  █                                                █
  █                                                █
  █   » Shodan Reconnaissance «                    █
  █   » By: Ractiurd «                             █
  █                                                █
  █▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█

  [ twitter.com/ractiurd  ]
  [ facebook.com/Ractiurd ]
`

func main() {
	flag.Usage = func() {
		// Show your existing banner
		displayLogo()

		fmt.Printf("\n%sUSAGE%s\n", green, reset)
		fmt.Printf("  %s [OPTIONS] -t target.com\n", filepath.Base(os.Args[0]))
		fmt.Printf("  %s [OPTIONS] -asn AS12345\n", filepath.Base(os.Args[0]))
		fmt.Printf("  %s [OPTIONS] -org \"Company\"\n\n", filepath.Base(os.Args[0]))

		fmt.Printf("%sOPTIONS%s\n", green, reset)
		fmt.Println("  -t string    Target domain")
		fmt.Println("  -asn string  Search by ASN")
		fmt.Println("  -org string  Search by organization")
		fmt.Println("  -api string  Shodan API key")
		fmt.Println("  -capi string Change/update saved Shodan API key")
		fmt.Println("  -c           Choose dorks")
		fmt.Println("  -s           Subdomains only")
		fmt.Println("  -i           IPs only")
		fmt.Println("  -o string    Save to file")
		fmt.Println("  -r string    Comma-separated list of HTTP status codes (e.g. 200,404)")
		fmt.Println("  -h           Show help\n")

		fmt.Printf("%sEXAMPLES%s\n", green, reset)
		fmt.Printf("  %s -t example.com\n", filepath.Base(os.Args[0]))
		fmt.Printf("  %s -asn AS15169 -o ips.txt\n", filepath.Base(os.Args[0]))
		fmt.Printf("  %s -org \"Cloudflare\" -s\n", filepath.Base(os.Args[0]))
		fmt.Printf("  %s -t example.com -r 200,404\n", filepath.Base(os.Args[0]))
		fmt.Printf("  %s -capi \"YOUR_NEW_API_KEY\"\n", filepath.Base(os.Args[0]))
		fmt.Printf("  %s -asn AS15169 -s\n", filepath.Base(os.Args[0]))

		os.Exit(0)
	}

	// Updated argument parser to include -capi
	chooseDork, org, asn, parsedAPIKey, target, printSub, printIPs, output, help, statusCodes, changeAPI := parseCommandLineArguments()

	if help {
		flag.Usage()
		os.Exit(0)
	}

	// Handle API key change first
	if changeAPI != "" {
		if err := updateAPIKey(changeAPI); err != nil {
			log.Fatalf("Error updating API key: %v", err)
		}
		fmt.Println("API key successfully updated!")
		os.Exit(0)
	}

	displayLogo()

	apiKey := getShodanAPIKey()
	if apiKey == "" {
		log.Fatal("Failed to get Shodan API key")
	}

	if parsedAPIKey != "" {
		apiKey = parsedAPIKey
	}

	switch {
	case asn != "" && org == "" && target == "":
		// ASN search mode
		handleASNSearch(apiKey, asn, printSub, printIPs, statusCodes)
	case org != "" && target == "" && asn == "":
		// Org search mode
		handleOrgSearch(apiKey, org, printSub, printIPs, statusCodes)
	case target != "" && org == "" && asn == "":
		// Domain search mode
		handleTargetSearch(apiKey, target, chooseDork, printSub, printIPs, statusCodes)
	default:
		log.Fatal("Invalid combination of arguments. Please specify either -t, -asn, or -org")
	}

	if output != "" {
		if err := writeOutputToFile(output); err != nil {
			log.Fatal("Error writing output:", err)
		}
	} else {
		printUniqueMapToStdout()
	}
}

// New function to handle ASN search with subdomain support
func handleASNSearch(apiKey, asn string, printSub, printIPs bool, statusCodes string) {
	dork := fmt.Sprintf("asn:\"%s\"", asn)
	if statusCodes != "" {
		dork += fmt.Sprintf(" http.status:%s", statusCodes)
	}
	
	matches := performShodanSearch(apiKey, dork)
	
	// Default to showing both if neither flag is set
	showSubs := printSub || (!printSub && !printIPs)
	showIPs := printIPs || (!printSub && !printIPs)
	
	if showSubs {
		printASNSubdomains(matches)
	}
	
	if showIPs {
		printASNIPs(matches)
	}
}

// New function to handle Org search with subdomain support
func handleOrgSearch(apiKey, org string, printSub, printIPs bool, statusCodes string) {
	dork := fmt.Sprintf("org:\"%s\"", org)
	if statusCodes != "" {
		dork += fmt.Sprintf(" http.status:%s", statusCodes)
	}
	
	matches := performShodanSearch(apiKey, dork)
	
	// Default to showing both if neither flag is set
	showSubs := printSub || (!printSub && !printIPs)
	showIPs := printIPs || (!printSub && !printIPs)
	
	if showSubs {
		printASNSubdomains(matches)
	}
	
	if showIPs {
		printASNIPs(matches)
	}
}

// New function to extract subdomains from ASN/Org search results
func printASNSubdomains(matches []interface{}) {
	for _, match := range matches {
		hostnames, ok := match.(map[string]interface{})["hostnames"].([]interface{})
		if ok && len(hostnames) > 0 {
			for _, hostname := range hostnames {
				if subdomain, ok := hostname.(string); ok && subdomain != "" {
					processAndPrintSubdomain(subdomain)
				}
			}
		}
	}
}

// New function to extract IPs from ASN/Org search results
func printASNIPs(matches []interface{}) {
	for _, match := range matches {
		ipString, ok := match.(map[string]interface{})["ip_str"].(string)
		if ok && ipString != "" {
			processAndPrintSubdomain(ipString)
		}
	}
}

// updateAPIKey deletes the old API key file and saves a new one
func updateAPIKey(newAPIKey string) error {
	// Get user's home directory
	usr, err := user.Current()
	if err != nil {
		return fmt.Errorf("could not get user home directory: %v", err)
	}

	// Construct the API key file path
	apiKeyPath := filepath.Join(usr.HomeDir, "go", "pkg", "shodanapikey.txt")

	// Remove existing API key file if it exists
	if _, err := os.Stat(apiKeyPath); err == nil {
		if err := os.Remove(apiKeyPath); err != nil {
			return fmt.Errorf("could not remove existing API key file: %v", err)
		}
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(apiKeyPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("could not create directory to save API key: %v", err)
	}

	// Write the new key to file
	if err := ioutil.WriteFile(apiKeyPath, []byte(newAPIKey), 0600); err != nil {
		return fmt.Errorf("could not save new API key to file: %v", err)
	}

	return nil
}

func displayLogo() {
	coloredLogo := fmt.Sprintf("%s", colorize(argusLogo, green))
	fmt.Println(coloredLogo)
}

func handleTargetSearch(apiKey, target string, chooseDork, printSub, printIPs bool, statusCodes string) {
	var dorkQuery string

	if chooseDork {
		dorkQuery = selectPredefinedDork(statusCodes)
	} else {
		dorkQuery = fmt.Sprintf(`ssl.cert.subject.CN:"%s"`, target)
	}

	// Fill in %s if present
	if strings.Contains(dorkQuery, "%s") {
		dorkQuery = fmt.Sprintf(dorkQuery, target)
	}

	// Append http status codes if provided
	if statusCodes != "" {
		dorkQuery = fmt.Sprintf("%s http.status:%s", dorkQuery, statusCodes)
	}

	matches := performShodanSearch(apiKey, dorkQuery)
	subdomainRegex := regexp.MustCompile(fmt.Sprintf(`.*\.%s$`, regexp.QuoteMeta(target)))

	// Default to showing both if neither flag is set
	showSubs := printSub || (!printSub && !printIPs)
	showIPs := printIPs || (!printSub && !printIPs)

	printResults(apiKey, target, matches, subdomainRegex, showSubs, showIPs)
}

func selectPredefinedDork(statusCodes string) string {
	fmt.Println("Choose a predefined dork:")
	for i, dork := range predefinedDorks {
		fmt.Printf("%d. %s\n", i+1, dork.Description)
	}

	var choice int
	fmt.Print("Enter the number of the dork: ")
	_, err := fmt.Scan(&choice)
	if err != nil || choice < 1 || choice > len(predefinedDorks) {
		fmt.Println("Invalid choice. Using default dork.")
		choice = 1
	}

	selected := predefinedDorks[choice-1].Query

	if statusCodes != "" {
		// Trim possible trailing status code already in dork and add proper filter
		if !strings.Contains(selected, "http.status:") {
			selected = fmt.Sprintf("%s http.status:%s", selected, statusCodes)
		}
	}

	return selected
}

func printUniqueMapToStdout() {
	for value := range uniqueMap {
		fmt.Println(value)
	}
}

func writeOutputToFile(outputFile string) error {
	// Read existing content if file exists
	if _, err := os.Stat(outputFile); err == nil {
		fileContent, err := ioutil.ReadFile(outputFile)
		if err != nil {
			return err
		}
		lines := strings.Split(string(fileContent), "\n")
		for _, line := range lines {
			uniqueMap[line] = true
		}
	}

	// Write all content to file
	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	for value := range uniqueMap {
		if _, err := fmt.Fprintln(file, value); err != nil {
			return err
		}
		fmt.Println(value) // Also print to stdout
	}

	return nil
}

func parseCommandLineArguments() (bool, string, string, string, string, bool, bool, string, bool, string, string) {
	help := flag.Bool("h", false, "Show help")
	apiKey := flag.String("api", "", "Shodan API Key")
	changeAPI := flag.String("capi", "", "Change/update saved Shodan API key")
	target := flag.String("t", "", "Target domain (e.g., target.com)")
	printSub := flag.Bool("s", false, "Print only subdomains")
	printIPs := flag.Bool("i", false, "Print only IP addresses")
	asn := flag.String("asn", "", "ASN number search")
	org := flag.String("org", "", "Org name must be put \"org\" ")
	chooseDork := flag.Bool("c", false, "Choose a predefined dork")
	output := flag.String("o", "", "Save the result in given filename")
	statusCodes := flag.String("r", "", "Comma-separated list of HTTP status codes (e.g. 200,404)")

	flag.Parse()

	return *chooseDork, *org, *asn, *apiKey, *target, *printSub, *printIPs, *output, *help, *statusCodes, *changeAPI
}

func performShodanSearch(apiKey, query string) []interface{} {
	apiURL := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s", apiKey, url.QueryEscape(query))

	response, err := http.Get(apiURL)
	if err != nil {
		log.Fatal("HTTP request error:", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(response.Body)
		log.Fatalf("Shodan API returned status %d: %s", response.StatusCode, string(body))
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal("Error reading response body:", err)
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		log.Fatal("Error decoding JSON:", err)
	}

	matches, ok := result["matches"].([]interface{})
	if !ok {
		log.Println("Warning: 'matches' is not an array. Attempting to handle this case.")
		if match, isNumber := result["matches"].(float64); isNumber {
			matches = []interface{}{match}
		} else {
			log.Fatal("Invalid 'matches' type in JSON response")
		}
	}

	return matches
}

func printResults(apiKey, target string, matches []interface{}, subdomainRegex *regexp.Regexp, printSub, printIP bool) {
	if printSub {
		printSubdomains(apiKey, target, matches, subdomainRegex)
		err := getSubdomains(apiKey, target)
		if err != nil {
			fmt.Println(err)
		}
		err1 := getSubdomainsjson(apiKey, target)
		if err1 != nil {
			fmt.Println(err1)
		}
	}

	if printIP {
		printIPAddresses(apiKey, matches)
	}
}

func printSubdomains(apiKey, target string, matches []interface{}, subdomainRegex *regexp.Regexp) {
	for _, match := range matches {
		hostnames, ok := match.(map[string]interface{})["hostnames"].([]interface{})
		if ok && len(hostnames) > 0 {
			subdomain := hostnames[0].(string)
			if subdomainRegex.MatchString(subdomain) {

				processAndPrintSubdomain(subdomain)
			}
		}
	}
}

func processAndPrintSubdomain(value string) {

	value = strings.TrimSpace(value)

	if _, exists := uniqueMap[value]; !exists {
		uniqueMap[value] = true
	}
}

func printIPAddresses(apiKey string, matches []interface{}) {
	for _, match := range matches {
		ipString, ok := match.(map[string]interface{})["ip_str"].(string)
		if ok {

			processAndPrintSubdomain(ipString)
		}
	}
}

func getSubdomains(apiKey, target string) error {
	url := fmt.Sprintf("https://api.shodan.io/dns/domain/%s", target)

	response, err := http.Get(fmt.Sprintf("%s?key=%s", url, apiKey))
	if err != nil {
		return fmt.Errorf("Error making HTTP request: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return fmt.Errorf("Error reading response body: %v", err)
		}

		subdomainRegex := regexp.MustCompile(fmt.Sprintf(`"([^"]*\.%s)`, target))
		matches := subdomainRegex.FindAllStringSubmatch(string(body), -1)

		if len(matches) > 0 && len(matches[0]) == 2 {
			for _, match := range matches {
				sub := match[1]
				processAndPrintSubdomain(sub)
			}
		} else {
			fmt.Printf("No subdomains found for %s.\n", target)
		}
	} else {
		return fmt.Errorf("Error: %d", response.StatusCode)
	}

	return nil
}

func getSubdomainsjson(apiKey, target string) error {
	url := fmt.Sprintf("%s%s?key=%s", shodanURL, target, apiKey)

	response, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("Error making HTTP request: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {
		var subdomainResponse SubdomainResponse
		err := json.NewDecoder(response.Body).Decode(&subdomainResponse)
		if err != nil {
			return fmt.Errorf("Error decoding JSON response: %v", err)
		}

		if len(subdomainResponse.SubDomains) > 0 {
			for _, subdomain := range subdomainResponse.SubDomains {
				result := fmt.Sprintf("%s.%s\n", subdomain, target)
				processAndPrintSubdomain(result)

			}
		} else {
			fmt.Printf("No subdomains found for %s.\n", target)
		}
	} else {
		return fmt.Errorf("Error: %d", response.StatusCode)
	}

	return nil
}

func asnipextracrt(apiKey, asn, statusCodes string) error {
	iteration := 0
	maxIterations := 10 // Safety limit

	// Base dork with ASN and optional status code filter
	baseDork := fmt.Sprintf("asn:\"%s\"", asn)
	if statusCodes != "" {
		baseDork = fmt.Sprintf("%s http.status:%s", baseDork, statusCodes)
	}

	for iteration < maxIterations {
		iteration++

		// Construct the API URL
		apiURL := fmt.Sprintf(
			"%s?key=%s&query=%s",
			shodanBaseURL,
			apiKey,
			url.QueryEscape(baseDork),
		)

		// Make API request
		resp, err := http.Get(apiURL)
		if err != nil {
			return fmt.Errorf("API request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := ioutil.ReadAll(resp.Body)
			return fmt.Errorf("Shodan API error: %s", string(body))
		}

		// Parse response
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response: %v", err)
		}

		var shodanResp ShodanResponse
		if err := json.Unmarshal(body, &shodanResp); err != nil {
			return fmt.Errorf("failed to parse JSON: %v", err)
		}

		// Process all IPs (no exclusion checks)
		for _, match := range shodanResp.Matches {
			ip := match.IPString
			processAndPrintSubdomain(ip)
		}

		fmt.Printf("Iteration %d: Found %d IPs\n", iteration, len(shodanResp.Matches))
	}

	return nil
}

func GetOrganizationIPs(apiKey, orgName, statusCodes string) error {
	// Build the query string with org filter
	query := fmt.Sprintf("org:\"%s\"", orgName)

	// Append http.status filter if statusCodes is provided
	if statusCodes != "" {
		query = fmt.Sprintf("%s http.status:%s", query, statusCodes)
	}

	// Escape the query for the URL
	url := fmt.Sprintf("%s?key=%s&query=%s", shodanBaseURL, apiKey, url.QueryEscape(query))

	response, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("error making Shodan API request: %v", err)
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %v", err)
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return fmt.Errorf("error decoding JSON: %v", err)
	}

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Shodan API request failed: %v", result["error"])
	}

	matches, ok := result["matches"].([]interface{})
	if !ok {
		return fmt.Errorf("unexpected response format: missing matches")
	}

	for _, host := range matches {
		hostMap, ok := host.(map[string]interface{})
		if !ok {
			continue
		}

		ip, ok := hostMap["ip_str"].(string)
		if !ok {
			continue
		}

		processAndPrintSubdomain(ip)
	}

	return nil
}

func colorize(text, color string) string {
	return fmt.Sprintf("%s%s%s", color, text, reset)
}

func getShodanAPIKey() string {
	// Get user's home directory
	usr, err := user.Current()
	if err != nil {
		log.Printf("Warning: Could not get user home directory: %v", err)
		return promptAndSaveAPIKey("")
	}

	// Construct the API key file path
	apiKeyPath := filepath.Join(usr.HomeDir, "go", "pkg", "shodanapikey.txt")

	// Try to read existing API key
	apiKey, err := ioutil.ReadFile(apiKeyPath)
	if err == nil && len(apiKey) > 0 {
		return strings.TrimSpace(string(apiKey))
	}

	// If we get here, either the file doesn't exist or is empty
	return promptAndSaveAPIKey(apiKeyPath)
}

func promptAndSaveAPIKey(apiKeyPath string) string {
	fmt.Print("Shodan API key not found. Please enter your Shodan API key: ")
	var apiKey string
	_, err := fmt.Scanln(&apiKey)
	if err != nil {
		log.Printf("Error reading API key: %v", err)
		return ""
	}

	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		log.Println("Error: Empty API key provided")
		return ""
	}

	// If we have a path, try to save the key
	if apiKeyPath != "" {
		// Create directory if it doesn't exist
		dir := filepath.Dir(apiKeyPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Printf("Warning: Could not create directory to save API key: %v", err)
			return apiKey
		}

		// Write the key to file
		if err := ioutil.WriteFile(apiKeyPath, []byte(apiKey), 0600); err != nil {
			log.Printf("Warning: Could not save API key to file: %v", err)
		} else {
			fmt.Println("API key saved for future use at:", apiKeyPath)
		}
	}

	return apiKey
}
