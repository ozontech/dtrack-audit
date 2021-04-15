package dtrack

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
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
			Text            string `xml:",chardata"`
			Type            string `xml:"type,attr"`
			Name            string `xml:"name"`
			Version         string `xml:"version"`
			Purl            string `xml:"purl"`
			Vulnerabilities []Finding
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

func (bom Bom) getByNameAndVersion(name, version string) int {
	for i, component := range bom.Components.Component {
		if strings.EqualFold(component.Name, name) && strings.EqualFold(component.Version, version) {
			return i
		}
	}
	return -1
}

func unmarshalXML(filePath string) *Bom {
	var bom Bom
	byteValue, err := ioutil.ReadFile(filePath)
	checkError(err)
	err = xml.Unmarshal(byteValue, &bom)
	checkError(err)
	return &bom
}

func printTeamCityMsg(action, output, testName string) {
	msg := TeamCityMsg{time.Now(), action, TeamCityPackageName, testName, output}
	jsonData, err := json.Marshal(msg)
	checkError(err)
	fmt.Println(string(jsonData))
}

func populateBomWithFindings(bom *Bom, findings []Finding) *Bom {
	for _, finding := range findings {
		i := bom.getByNameAndVersion(finding.Comp.Name, finding.Comp.Version)
		if i >= 0 {
			component := &bom.Components.Component[i]
			component.Vulnerabilities = append(component.Vulnerabilities, finding)
		}
	}
	return bom
}

func PrintForTeamCity(findings []Finding, config *Config) {
	bom := unmarshalXML(config.InputFileName)
	bom = populateBomWithFindings(bom, findings)
	for _, component := range bom.Components.Component {
		lib := component.Name + "@" + component.Version
		printTeamCityMsg("run", "", lib)
		if len(component.Vulnerabilities) > 0 {
			printTeamCityMsg("output", formatFinding(component.Vulnerabilities, config), lib)
			printTeamCityMsg("fail", "", lib)
		} else {
			printTeamCityMsg("pass", "", lib)
		}
	}
	if len(findings) > 0 {
		os.Exit(1)
	}
}
