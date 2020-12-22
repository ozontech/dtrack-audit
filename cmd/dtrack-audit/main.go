package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/ozonru/dtrack-audit/internal/dtrack"
	"log"
	"os"
	"strconv"
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
	var inputFileName, projectId, apiKey, apiUrl, severityFilter, projectName, projectVersion string
	var syncMode, autoCreateProject, useTeamCityOutput bool
	var uploadResult dtrack.UploadResult
	var timeout int

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Send SBOM file to Dependency Track for audit.\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of program:\n")
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "\nFields marked with (*) are required.\n")
	}

	syncMode, err := strconv.ParseBool(os.Getenv("DTRACK_SYNC_MODE"))

	if err != nil {
		syncMode = false
	}

	autoCreateProject, err = strconv.ParseBool(os.Getenv("DTRACK_AUTO_CREATE_PROJECT"))
	useTeamCityOutput, err = strconv.ParseBool(os.Getenv("DTRACK_TEAMCITY_OUTPUT"))

	if err != nil {
		autoCreateProject = false
	}

	flag.StringVar(&inputFileName, "i", "bom.xml", "Target SBOM file*")
	flag.StringVar(&projectId, "p", os.Getenv("DTRACK_PROJECT_ID"), "Project ID. Environment variable is DTRACK_PROJECT_ID")
	flag.StringVar(&projectName, "n", os.Getenv("DTRACK_PROJECT_NAME"), "Project name. It is used for auto creation of project. See option autoCreateProject for details. Environment variable is DTRACK_PROJECT_NAME")
	flag.StringVar(&projectVersion, "v", os.Getenv("DTRACK_PROJECT_VERSION"), "Project version. It is used for auto creation of project. See option autoCreateProject for details. Environment variable is DTRACK_PROJECT_VERSION")
	flag.StringVar(&apiKey, "k", os.Getenv("DTRACK_API_KEY"), "API Key*. Environment variable is DTRACK_API_KEY")
	flag.StringVar(&apiUrl, "u", os.Getenv("DTRACK_API_URL"), "API URL*. Environment variable is DTRACK_API_URL")
	flag.StringVar(&severityFilter, "g", os.Getenv("DTRACK_SEVERITY_FILTER"), "With Sync mode enabled show result and fail an audit if the results include a vulnerability with a severity of specified level or higher. Severity levels are: critical, high, medium, low, info, unassigned. Environment variable is DTRACK_SEVERITY_FILTER")
	flag.BoolVar(&syncMode, "s", syncMode, "Sync mode enabled. That means: upload SBOM file, wait for scan result, show it and exit with non-zero code. Environment variable is DTRACK_SYNC_MODE")
	flag.BoolVar(&autoCreateProject, "a", autoCreateProject, "Auto create project with projectName if it does not exist. Environment variable is DTRACK_AUTO_CREATE_PROJECT")
	flag.BoolVar(&useTeamCityOutput, "T", useTeamCityOutput, "Use TeamCity output. Environment variable is DTRACK_TEAMCITY_OUTPUT")
	flag.IntVar(&timeout, "t", 25, "Max timeout in second for polling API for project findings")
	flag.Parse()

	if apiKey == "" || apiUrl == "" {
		flag.Usage()
		os.Exit(1)
	}

	apiClient := dtrack.ApiClient{ApiKey: apiKey, ApiUrl: apiUrl}

	if autoCreateProject && projectId == "" {
		projectId, err = apiClient.LookupOrCreateProject(projectName, projectVersion)
		checkError(err)
	}

	if projectId == "" {
		flag.Usage()
		os.Exit(1)
	}

	uploadResult, err = apiClient.Upload(inputFileName, projectId)
	checkError(err)

	if uploadResult.Token != "" {
		fmt.Printf("SBOM file is successfully uploaded to DTrack API. Result token is %s\n", uploadResult.Token)
	}

	if uploadResult.Token != "" && syncMode {
		if useTeamCityOutput {
			printTeamCityMsg("run", "")
		}
		err := apiClient.PollTokenBeingProcessed(uploadResult.Token, time.After(time.Duration(timeout)*time.Second))
		checkError(err)
		findings, err := apiClient.GetFindings(projectId, severityFilter)
		checkError(err)
		if len(findings) > 0 {
			fmt.Printf("%d vulnerabilities found!\n\n", len(findings))
			for _, f := range findings {
				if useTeamCityOutput {
					printTeamCityMsg("output", formatFinding(f, apiClient))
				} else {
					fmt.Print(formatFinding(f, apiClient))
				}
			}
			if useTeamCityOutput {
				printTeamCityMsg("fail", "")
			}
			os.Exit(1)
		}
		if useTeamCityOutput {
			printTeamCityMsg("pass", "")
		}
	}
}

