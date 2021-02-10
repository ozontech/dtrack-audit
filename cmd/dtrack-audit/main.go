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

	config := new(Config)
	ParseFlagsAndEnvs(config)

	apiClient := dtrack.ApiClient{ApiKey: config.apiKey, ApiUrl: config.apiUrl}

	if config.autoCreateProject && config.projectId == "" {
		config.projectId, err = apiClient.LookupOrCreateProject(config.projectName, config.projectVersion)
		checkError(err)
	}

	uploadResult, err := apiClient.Upload(config.inputFileName, config.projectId)
	checkError(err)

	if uploadResult.Token != "" {
		fmt.Printf("SBOM file is successfully uploaded to DTrack API. Result token is %s\n", uploadResult.Token)
	}

	if uploadResult.Token != "" && config.syncMode {
		if config.useTeamCityOutput {
			printTeamCityMsg("run", "")
		}
		err := apiClient.PollTokenBeingProcessed(uploadResult.Token, time.After(time.Duration(config.timeout)*time.Second))
		checkError(err)
		findings, err := apiClient.GetFindings(config.projectId, config.severityFilter)
		checkError(err)
		if len(findings) > 0 {
			fmt.Printf("%d vulnerabilities found!\n\n", len(findings))
			for _, f := range findings {
				if config.useTeamCityOutput {
					printTeamCityMsg("output", formatFinding(f, apiClient))
				} else {
					fmt.Print(formatFinding(f, apiClient))
				}
			}
			if config.useTeamCityOutput {
				printTeamCityMsg("fail", "")
			}
			os.Exit(1)
		}
		if config.useTeamCityOutput {
			printTeamCityMsg("pass", "")
		}
	}
}
