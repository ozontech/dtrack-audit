package main

import (
	"encoding/json"
	"fmt"
	"github.com/ozonru/dtrack-audit/internal/dtrack"
	"log"
	"os"
	"time"
)

type TeamCityMsg struct {
	Time    time.Time
	Action  string
	Package string
	Test    string
	Output  string
}

const TeamCityPackageName = "github.com/ozonru/dtrack-audit/cmd/dtrack-audit"
const TeamCityTestName = "TestVulnerabilities"

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

func printTeamCityMsg(action, output string) {
	msg := TeamCityMsg{time.Now(), action, TeamCityPackageName, TeamCityTestName, output}
	jsonData, err := json.Marshal(msg)
	checkError(err)
	fmt.Println(string(jsonData))
}

func main() {
	var err error

	config := &dtrack.Config{}
	dtrack.ParseFlagsAndEnvs(config)

	if config.ApiKey == "" || config.ApiUrl == "" {
		dtrack.Usage()
		os.Exit(1)
	}

	// We need at least  apiKey and apiUrl to call Dtrack API
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

	uploadResult, err := apiClient.Upload(config.InputFileName, config.ProjectId)
	checkError(err)

	if uploadResult.Token != "" {
		fmt.Printf("SBOM file is successfully uploaded to DTrack API. Result token is %s\n", uploadResult.Token)
	}

	if uploadResult.Token != "" && config.SyncMode {
		if config.UseTeamCityOutput {
			printTeamCityMsg("run", "")
		}
		err := apiClient.PollTokenBeingProcessed(uploadResult.Token, time.After(time.Duration(config.Timeout)*time.Second))
		checkError(err)
		findings, err := apiClient.GetFindings(config.ProjectId, config.SeverityFilter)
		checkError(err)
		if len(findings) > 0 {
			fmt.Printf("%d vulnerabilities found!\n\n", len(findings))
			for _, f := range findings {
				if config.UseTeamCityOutput {
					printTeamCityMsg("output", formatFinding(f, apiClient))
				} else {
					fmt.Print(formatFinding(f, apiClient))
				}
			}
			if config.UseTeamCityOutput {
				printTeamCityMsg("fail", "")
			}
			os.Exit(1)
		}
		if config.UseTeamCityOutput {
			printTeamCityMsg("pass", "")
		}
	}
}
