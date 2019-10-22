package main

import (
	"flag"
	"fmt"
	"github.com/ozonru/dtrack-audit/internal/dtrack"
	"log"
	"os"
	"time"
)

func checkError(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func main() {
	var inputFileName, projectId, apiKey, apiUrl, severityFilter string
	var syncMode bool
	var uploadResult dtrack.UploadResult
	var timeout int

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Send SBOM file to Dependency Track for audit.\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of program:\n")
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "\nFields marked with (*) are required.\n")
	}

	flag.StringVar(&inputFileName, "i", "bom.xml", "Target SBOM file*")
	flag.StringVar(&projectId, "p", os.Getenv("DTRACK_PROJECT_ID"), "Project ID*")
	flag.StringVar(&apiKey, "k", os.Getenv("DTRACK_API_KEY"), "API Key*")
	flag.StringVar(&apiUrl, "u", os.Getenv("DTRACK_API_URL"), "API URL*")
	flag.StringVar(&severityFilter, "g", os.Getenv("DTRACK_SEVERITY_FILTER"), "With Sync mode enabled show result and fail an audit if the results include a vulnerability with a severity of specified level or higher. Severity levels are: critical, high, medium, low, info, unassigned")
	flag.BoolVar(&syncMode, "s", false, "Sync mode enabled. It is meaning: upload SBOM file, wait for scan result, show it and exit with non-zero code")
	flag.IntVar(&timeout, "t", 25, "Max timeout in second for polling API for project findings")
	flag.Parse()

	if projectId == "" || apiKey == "" || apiUrl == "" {
		flag.Usage()
		os.Exit(1)
	}

	apiClient := dtrack.ApiClient{ApiKey: apiKey, ApiUrl: apiUrl}
	uploadResult, err := apiClient.Upload(inputFileName, projectId)
	checkError(err)

	if uploadResult.Token != "" {
		log.Printf("SBOM file is successfully uploaded to DTrack API. Result token is %s\n", uploadResult.Token)
	}

	if uploadResult.Token != "" && syncMode {
		err := apiClient.PollTokenBeingProcessed(uploadResult.Token, time.After(time.Duration(timeout)*time.Second))
		checkError(err)
		findings, err := apiClient.GetFindings(projectId, severityFilter)
		checkError(err)
		if len(findings) > 0 {
			fmt.Printf("%d vulnerabilities found!\n\n", len(findings))
			for _, f := range findings {
				fmt.Printf(" > %s: %s\n", f.Vuln.Severity, f.Vuln.Title)
				fmt.Printf("   Component: %s %s\n", f.Comp.Name, f.Comp.Version)
				fmt.Printf("   More info: %s\n\n", apiClient.GetVulnViewUrl(f.Vuln))
			}
			os.Exit(1)
		}
	}
}
