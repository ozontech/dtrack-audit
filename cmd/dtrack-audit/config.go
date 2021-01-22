package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	inputFileName     string
	projectId         string
	projectName       string
	projectVersion    string
	apiKey            string
	apiUrl            string
	severityFilter    string
	syncMode          bool
	autoCreateProject bool
	useTeamCityOutput bool
	timeout           int
}

func parseFlagsAndEnvs(config *Config) {
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

	config.autoCreateProject, err = strconv.ParseBool(os.Getenv("DTRACK_AUTO_CREATE_PROJECT"))
	config.useTeamCityOutput, err = strconv.ParseBool(os.Getenv("DTRACK_TEAMCITY_OUTPUT"))

	if err != nil {
		config.autoCreateProject = false
	}

	flag.StringVar(&config.inputFileName, "i", "bom.xml",
		"Target SBOM file*")
	flag.StringVar(&config.projectId, "p", os.Getenv("DTRACK_PROJECT_ID"),
		"Project ID. Environment variable is DTRACK_PROJECT_ID")
	flag.StringVar(&config.projectName, "n", os.Getenv("DTRACK_PROJECT_NAME"),
		"Project name. It is used for auto creation of project. See option autoCreateProject for details. "+
			"Environment variable is DTRACK_PROJECT_NAME")
	flag.StringVar(&config.projectVersion, "v", os.Getenv("DTRACK_PROJECT_VERSION"),
		"Project version. It is used for auto creation of project. See option autoCreateProject for details. "+
			"Environment variable is DTRACK_PROJECT_VERSION")
	flag.StringVar(&config.apiKey, "k", os.Getenv("DTRACK_API_KEY"),
		"API Key*. Environment variable is DTRACK_API_KEY")
	flag.StringVar(&config.apiUrl, "u", os.Getenv("DTRACK_API_URL"),
		"API URL*. Environment variable is DTRACK_API_URL")
	flag.StringVar(&config.severityFilter, "g", os.Getenv("DTRACK_SEVERITY_FILTER"),
		"With Sync mode enabled show result and fail an audit if the results include a vulnerability with a "+
			"severity of specified level or higher. Severity levels are: critical, high, medium, low, info, "+
			"unassigned. Environment variable is DTRACK_SEVERITY_FILTER")
	flag.BoolVar(&config.syncMode, "s", syncMode, "Sync mode enabled. That means: upload SBOM file, "+
		"wait for scan result, show it and exit with non-zero code. Environment variable is DTRACK_SYNC_MODE")
	flag.BoolVar(&config.autoCreateProject, "a", config.autoCreateProject,
		"Auto create project with projectName if it does not exist. Environment variable "+
			"is DTRACK_AUTO_CREATE_PROJECT")
	flag.BoolVar(&config.useTeamCityOutput, "T", config.useTeamCityOutput,
		"Use TeamCity output. Environment variable is DTRACK_TEAMCITY_OUTPUT")
	flag.IntVar(&config.timeout, "t", 25,
		"Max timeout in second for polling API for project findings")
	flag.Parse()

	if config.apiKey == "" || config.apiUrl == "" {
		flag.Usage()
		os.Exit(1)
	}
}
