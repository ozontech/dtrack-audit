package main

import (
	"errors"
	"fmt"
	"github.com/ozonru/dtrack-audit/internal/dtrack"
	"log"
	"os"
	"strings"
	"time"
)

func checkError(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func formatFinding(findings []dtrack.Finding, apiClient dtrack.ApiClient) string {
	var finalString []string
	for _, f := range findings {
		finalString = append(finalString, fmt.Sprintf(
			" > %s: %s\n   Component: %s %s\n   More info: %s\n\n",
			f.Vuln.Severity, f.Vuln.VulnId, f.Comp.Name, f.Comp.Version, apiClient.GetVulnViewUrl(f.Vuln)))
	}
	return strings.Join(finalString[:], "")
}

func findVulnerabilities(apiClient dtrack.ApiClient, config *Config) ([]dtrack.Finding, error) {
	uploadResult, err := apiClient.Upload(config.inputFileName, config.projectId)
	checkError(err)
	if uploadResult.Token != "" {
		fmt.Printf("SBOM file is successfully uploaded to DTrack API. Result token is %s\n", uploadResult.Token)
		err := apiClient.PollTokenBeingProcessed(
			uploadResult.Token, time.After(time.Duration(config.timeout)*time.Second))
		checkError(err)
		findings, err := apiClient.GetFindings(config.projectId, config.severityFilter)
		checkError(err)
		return findings, err
	}
	return nil, errors.New("token was not received")
}

func PrintForUser(apiClient dtrack.ApiClient, config *Config) {
	findings, err := findVulnerabilities(apiClient, config)
	checkError(err)
	if len(findings) > 0 {
		fmt.Printf("%d vulnerabilities found!\n\n", len(findings))
		fmt.Print(formatFinding(findings, apiClient))
		os.Exit(1)
	}
}

func main() {
	var err error

	config := new(Config)
	ParseFlagsAndEnvs(config)

	apiClient := dtrack.ApiClient{ApiKey: config.apiKey, ApiUrl: config.apiUrl}

	if config.autoCreateProject && config.projectId == "" {
		config.projectId, err = apiClient.LookupOrCreateProject(config.projectName, config.projectVersion)
		checkError(err)
	}

	if config.syncMode {
		if config.useTeamCityOutput {
			PrintForTeamCity(apiClient, config)
		} else {
			PrintForUser(apiClient, config)
		}
	}
}
