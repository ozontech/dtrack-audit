package main

import (
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
	var err error

	config := &dtrack.Config{}
	dtrack.ParseFlagsAndEnvs(config)

	// We need at least apiKey and apiUrl to call Dtrack API
	if config.ApiKey == "" || config.ApiUrl == "" {
		dtrack.Usage()
		os.Exit(1)
	}

	apiClient := dtrack.ApiClient{ApiKey: config.ApiKey, ApiUrl: config.ApiUrl}

	// Try to find project by name or create it
	if config.AutoCreateProject && config.ProjectId == "" {
		config.ProjectId, err = apiClient.LookupOrCreateProject(config.ProjectName, config.ProjectVersion)
		checkError(err)
	}

	// ProjectId is also required to call Dtrack API and deal with projects
	if config.ProjectId == "" {
		dtrack.Usage()
		os.Exit(1)
	}

	uploadResult, err := apiClient.Upload(config.InputFileName, config.ProjectId)
	checkError(err)

	if uploadResult.Token != "" {
		fmt.Printf("SBOM file is successfully uploaded to DTrack API. Result token is %s\n", uploadResult.Token)
	}

	// In Sync mode we're waiting for findings from Dtrack
	if uploadResult.Token != "" && config.SyncMode {
		err := apiClient.PollTokenBeingProcessed(
			uploadResult.Token, time.After(time.Duration(config.Timeout)*time.Second))
		checkError(err)

		findings, err := apiClient.GetFindings(config.ProjectId, config.SeverityFilter)
		checkError(err)

		if config.UseTeamCityOutput {
			dtrack.PrintForTeamCity(findings, config)
		} else {
			dtrack.PrintForUser(findings, config)
		}
		// For CI/CD integration
		if len(findings) > 0 {
			os.Exit(1)
		}
	}
}
