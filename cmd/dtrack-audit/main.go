package main

import (
	"github.com/ozonru/dtrack-audit/internal/dtrack"
	"log"
	"os"
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
		if config.UseTeamCityOutput {
			dtrack.PrintForTeamCity(apiClient, config)
		} else {
			dtrack.PrintForUser(apiClient, config)
		}
	}
}
