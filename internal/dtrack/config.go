package dtrack

import (
	"flag"
	"fmt"
	"os"
	"strconv"
)

var defaultTimeout = 30
var defaultFileName = "bom.xml"

type Config struct {
	InputFileName     string
	ProjectId         string
	ProjectName       string
	ProjectVersion    string
	ApiKey            string
	ApiUrl            string
	SeverityFilter    string
	SyncMode          bool
	AutoCreateProject bool
	UseTeamCityOutput bool
	Timeout           int
}

func Usage() {
	flag.Usage()
}

func generateHelp() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Send SBOM file to Dependency Track for audit.\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of program:\n")
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "\nFields marked with (*) are required.\n")
	}
}

func getEnvBool(envName string) bool {
	envVar, err := strconv.ParseBool(os.Getenv(envName))
	if err != nil {
		envVar = false
	}
	return envVar
}

func ParseFlagsAndEnvs(config *Config) {
	generateHelp()

	flag.StringVar(
		&config.InputFileName,
		"i",
		defaultFileName,
		"Target SBOM file*")
	flag.StringVar(
		&config.ProjectId,
		"p",
		os.Getenv("DTRACK_PROJECT_ID"),
		"Project ID. Environment variable is DTRACK_PROJECT_ID")
	flag.StringVar(
		&config.ProjectName,
		"n",
		os.Getenv("DTRACK_PROJECT_NAME"),
		"Project name. It is used for auto creation of project. See option AutoCreateProject for details. "+
			"Environment variable is DTRACK_PROJECT_NAME")
	flag.StringVar(
		&config.ProjectVersion,
		"v",
		os.Getenv("DTRACK_PROJECT_VERSION"),
		"Project version. It is used for auto creation of project. See option AutoCreateProject for details. "+
			"Environment variable is DTRACK_PROJECT_VERSION")
	flag.StringVar(
		&config.ApiKey,
		"k",
		os.Getenv("DTRACK_API_KEY"),
		"API Key*. Environment variable is DTRACK_API_KEY")
	flag.StringVar(
		&config.ApiUrl,
		"u",
		os.Getenv("DTRACK_API_URL"),
		"API URL*. Environment variable is DTRACK_API_URL")
	flag.StringVar(
		&config.SeverityFilter,
		"g",
		os.Getenv("DTRACK_SEVERITY_FILTER"),
		"With Sync mode enabled show result and fail an audit if the results include a vulnerability with a "+
			"severity of specified level or higher. Severity levels are: critical, high, medium, low, info, "+
			"unassigned. Environment variable is DTRACK_SEVERITY_FILTER")
	flag.BoolVar(
		&config.SyncMode,
		"s",
		getEnvBool("DTRACK_SYNC_MODE"),
		"Sync mode enabled. That means: upload SBOM file, wait for scan result, "+
			"show it and exit with non-zero code. Environment variable is DTRACK_SYNC_MODE")
	flag.BoolVar(
		&config.AutoCreateProject,
		"a",
		getEnvBool("DTRACK_AUTO_CREATE_PROJECT"),
		"Auto create project with projectName if it does not exist. Environment variable "+
			"is DTRACK_AUTO_CREATE_PROJECT")
	flag.BoolVar(
		&config.UseTeamCityOutput,
		"T",
		getEnvBool("DTRACK_TEAMCITY_OUTPUT"),
		"Use TeamCity output. Environment variable is DTRACK_TEAMCITY_OUTPUT")
	flag.IntVar(
		&config.Timeout,
		"t",
		defaultTimeout,
		"Max timeout in second for polling API for project findings")
	flag.Parse()
}
