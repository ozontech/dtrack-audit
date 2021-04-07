package dtrack

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

func getVulnViewUrl(v Vulnerability, config *Config) string {
	uv := url.Values{}
	uv.Set("source", v.Source)
	uv.Set("vulnId", v.VulnId)
	return config.ApiUrl + "/vulnerability?" + uv.Encode()
}

func formatFinding(findings []Finding, config *Config) string {
	var finalString []string
	for _, f := range findings {
		finalString = append(finalString, fmt.Sprintf(
			" > %s: %s\n   Component: %s %s\n   More info: %s\n\n",
			f.Vuln.Severity, f.Vuln.VulnId, f.Comp.Name, f.Comp.Version, getVulnViewUrl(f.Vuln, config)))
	}
	return strings.Join(finalString[:], "")
}

func PrintForUser(findings []Finding, config *Config) {
	if len(findings) > 0 {
		fmt.Printf("%d vulnerabilities found!\n\n", len(findings))
		fmt.Print(formatFinding(findings, config))
		os.Exit(1)
	}
}
