package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/agentram/dtrack-audit/internal/dtrack"
	"log"
	"os"
	"time"
)

func checkError(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func formatFinding(f dtrack.Finding, apiClient dtrack.ApiClient) string {
	return fmt.Sprintf(
		" > %s: %s\n   Component: %s %s\n   More info: %s\n\n",
		f.Vuln.Severity, f.Vuln.Title, f.Comp.Name, f.Comp.Version, apiClient.GetVulnViewUrl(f.Vuln))
}

func findVulnerabilities(apiClient dtrack.ApiClient, config *Config) (int, []dtrack.Finding, error) {
	uploadResult, err := apiClient.Upload(config.inputFileName, config.projectId)
	checkError(err)
	if uploadResult.Token != "" {
		fmt.Printf("SBOM file is successfully uploaded to DTrack API. Result token is %s\n", uploadResult.Token)
		err := apiClient.PollTokenBeingProcessed(uploadResult.Token, time.After(time.Duration(config.timeout)*time.Second))
		checkError(err)
		findings, err := apiClient.GetFindings(config.projectId, config.severityFilter)
		checkError(err)
		return len(findings), findings, err
	}
	return 0, nil, errors.New("token not found")
}

func findAndPrintForUser(apiClient dtrack.ApiClient, config *Config) (int, []dtrack.Finding) {
	vulnerabilitiesCount, findings, err := findVulnerabilities(apiClient, config)
	checkError(err)
	if vulnerabilitiesCount > 0 {
		fmt.Printf("%d vulnerabilities found!\n\n", vulnerabilitiesCount)
		for _, f := range findings {
			fmt.Print(formatFinding(f, apiClient))
		}
	}
	return vulnerabilitiesCount, findings
}

func main() {
	var err error
	config := new(Config)
	parseFlagsAndEnvs(config)

	apiClient := dtrack.ApiClient{ApiKey: config.apiKey, ApiUrl: config.apiUrl}

	if config.autoCreateProject && config.projectId == "" {
		config.projectId, err = apiClient.LookupOrCreateProject(config.projectName, config.projectVersion)
		checkError(err)
	}

	if config.projectId == "" {
		flag.Usage()
		os.Exit(1)
	}

	if config.syncMode {
		var vulnerabilitiesCount int
		if config.useTeamCityOutput {
			vulnerabilitiesCount, _ = findAndPrintForTeamCity(apiClient, config)
		} else {
			vulnerabilitiesCount, _ = findAndPrintForUser(apiClient, config)
		}
		if vulnerabilitiesCount > 0 {
			os.Exit(1)
		}
	}
}
