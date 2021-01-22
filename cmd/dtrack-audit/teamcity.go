package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/agentram/dtrack-audit/internal/dtrack"
	"io/ioutil"
	"os"
	"time"
)

const TeamCityPackageName = "github.com/ozonru/dtrack-audit/cmd/dtrack-audit"

type Bom struct {
	XMLName      xml.Name `xml:"bom"`
	Text         string   `xml:",chardata"`
	Xmlns        string   `xml:"xmlns,attr"`
	Version      string   `xml:"version,attr"`
	SerialNumber string   `xml:"serialNumber,attr"`
	Components   struct {
		Text      string `xml:",chardata"`
		Component []struct {
			Text                 string `xml:",chardata"`
			Type                 string `xml:"type,attr"`
			Name                 string `xml:"name"`
			Version              string `xml:"version"`
			Purl                 string `xml:"purl"`
			HasVulnerabilities   bool
			VulnerabilitiesDiscr string
		} `xml:"component"`
	} `xml:"components"`
}

type TeamCityMsg struct {
	Time    time.Time
	Action  string
	Package string
	Test    string
	Output  string
}

func unmarshalXML(filePath string) []Bom {
	result := make([]Bom, 0)
	xmlFile, err := os.Open(filePath)
	checkError(err)
	defer xmlFile.Close()
	byteValue, _ := ioutil.ReadAll(xmlFile)
	err = xml.Unmarshal(byteValue, &result)
	checkError(err)
	return result
}

func printTeamCityMsg(action, output, testName string) {
	msg := TeamCityMsg{time.Now(), action, TeamCityPackageName, testName, output}
	jsonData, err := json.Marshal(msg)
	checkError(err)
	fmt.Println(string(jsonData))
}

func populateBomWithFindings(bom []Bom, findings []dtrack.Finding, apiClient dtrack.ApiClient) []Bom {
	for _, finding := range findings {
		for _, v := range bom {
			lib := v.Components.Component
			for i := range lib {
				if lib[i].Name == finding.Comp.Name && lib[i].Version == finding.Comp.Version {
					lib[i].HasVulnerabilities = true
					lib[i].VulnerabilitiesDiscr += formatFinding(finding, apiClient)
					break
				}
			}
		}
	}
	return bom
}

func findAndPrintForTeamCity(apiClient dtrack.ApiClient, config *Config) (int, []dtrack.Finding) {
	bom := unmarshalXML(config.inputFileName)
	vulnerabilitiesCount, findings, err := findVulnerabilities(apiClient, config)
	checkError(err)
	bom = populateBomWithFindings(bom, findings, apiClient)
	for _, b := range bom {
		libs := b.Components.Component
		for i := range libs {
			lib := libs[i].Name + "@" + libs[i].Version
			printTeamCityMsg("run", "", lib)
			if libs[i].HasVulnerabilities {
				printTeamCityMsg("output", libs[i].VulnerabilitiesDiscr, lib)
				printTeamCityMsg("fail", "", lib)
			} else {
				printTeamCityMsg("pass", "", lib)
			}
		}
	}
	return vulnerabilitiesCount, findings
}
