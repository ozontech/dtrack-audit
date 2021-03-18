package dtrack

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

func formatFinding(findings []Finding, apiClient ApiClient) string {
	var finalString []string
	for _, f := range findings {
		finalString = append(finalString, fmt.Sprintf(
			" > %s: %s\n   Component: %s %s\n   More info: %s\n\n",
			f.Vuln.Severity, f.Vuln.VulnId, f.Comp.Name, f.Comp.Version, apiClient.GetVulnViewUrl(f.Vuln)))
	}
	return strings.Join(finalString[:], "")
}

func findVulnerabilities(apiClient ApiClient, config *Config) ([]Finding, error) {
	uploadResult, err := apiClient.Upload(config.InputFileName, config.ProjectId)
	checkError(err)
	if uploadResult.Token != "" {
		fmt.Printf("SBOM file is successfully uploaded to DTrack API. Result token is %s\n", uploadResult.Token)
		err := apiClient.PollTokenBeingProcessed(
			uploadResult.Token, time.After(time.Duration(config.Timeout)*time.Second))
		checkError(err)
		findings, err := apiClient.GetFindings(config.ProjectId, config.SeverityFilter)
		checkError(err)
		return findings, err
	}
	return nil, errors.New("token was not received")
}

func PrintForUser(apiClient ApiClient, config *Config) {
	findings, err := findVulnerabilities(apiClient, config)
	checkError(err)
	if len(findings) > 0 {
		fmt.Printf("%d vulnerabilities found!\n\n", len(findings))
		fmt.Print(formatFinding(findings, apiClient))
		os.Exit(1)
	}
}
