package main

import (
	"errors"
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

func findVulnerabilities(apiClient dtrack.ApiClient, config *dtrack.Config) ([]dtrack.Finding, error) {
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

func main() {
	var err error

	config := &dtrack.Config{}
	dtrack.ParseFlagsAndEnvs(config)

	// We need at least apiKey and apiUrl to call Dtrack API
	if config.ApiKey == "" || config.ApiUrl == "" {
		dtrack.Usage()
		os.Exit(1)
	}

	apiClient := dtrack.ApiClient{ApiKey: config.ApiKey, ApiUrl: config.ApiUrl}

	if config.AutoCreateProject && config.ProjectId == "" {
		config.ProjectId, err = apiClient.LookupOrCreateProject(config.ProjectName, config.ProjectVersion)
		checkError(err)
	}

	// projectId is also required to call Dtrack API and deal with projects
	if config.ProjectId == "" {
		dtrack.Usage()
		os.Exit(1)
	}

	if config.SyncMode {
		findings, err := findVulnerabilities(apiClient, config)
		checkError(err)
		if config.UseTeamCityOutput {
			dtrack.PrintForTeamCity(findings, config)
		} else {
			dtrack.PrintForUser(findings, config)
		}
	}
}
