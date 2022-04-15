package main

import (
	"fmt"
	"os"
	"time"

	"github.com/ozontech/dtrack-audit/internal/dtrack"
)

func checkError(e error) {
	if e != nil {
		fmt.Printf("[Dtrack Audit Error]: %s\n", e)
		os.Exit(0)
	}
}

func main() {
	var err error

	config := &dtrack.Config{}
	dtrack.ParseFlagsAndEnvs(config)

	// We need at least apiKey and apiUrl to call Dtrack API
	if config.ApiKey == "" || config.ApiUrl == "" {
		dtrack.Usage()
		os.Exit(0)
	}

	versionDifferent := false
	apiClient := dtrack.ApiClient{ApiKey: config.ApiKey, ApiUrl: config.ApiUrl}

	// Try to find project by name or create it
	if config.AutoCreateProject && config.ProjectId == "" {
		config.ProjectId, versionDifferent, err = apiClient.LookupOrCreateProject(config.ProjectName, config.ProjectVersion)
		checkError(err)
	}

	// ProjectId is also required to call Dtrack API and deal with projects
	if config.ProjectId == "" {
		fmt.Println("ProjectId is required if auto create project (-a) not supplied")
		dtrack.Usage()
		os.Exit(0)
	}

	uploadResult, err := apiClient.Upload(config.InputFileName, config.ProjectId)
	checkError(err)

	if uploadResult.Token != "" {
		fmt.Printf("SBOM file is successfully uploaded to DTrack API. Result token is %s\n", uploadResult.Token)
	}

	if versionDifferent && config.ProjectVersion != "" {
		err = apiClient.UpdateProjectVersion(config.ProjectId, config.ProjectName, config.ProjectVersion)
		checkError(err)
	}

	// In Sync mode we're waiting for findings from Dtrack
	if uploadResult.Token != "" && config.SyncMode {
		fmt.Println("In Sync mode we're waiting for findings from DTrack")
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
		// Break corresponding CI/CD job to make developers
		// pay attention to findings
		if len(findings) > 0 {
			os.Exit(1)
		}
	}
}
