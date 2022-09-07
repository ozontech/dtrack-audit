package dtrack

import (
	"bytes"
	"crypto/tls"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	BOM_UPLOAD_URL       = "/api/v1/bom"
	PROJECT_FINDINGS_URL = "/api/v1/finding/project"
	PROJECT_LOOKUP_URL   = "/api/v1/project/lookup"
	PROJECT_CREATE_URL   = "/api/v1/project"
	PROJECT_ALL_URL      = "/api/v1/project"
	PROJECT_UPDATE_URL   = "/api/v1/project"
	BOM_TOKEN_URL        = "/api/v1/bom/token"
	API_POLLING_STEP     = 5 * time.Second
)

func checkError(e error) {
	if e != nil {
		fmt.Printf("[Dtrack API Client Error]: %s\n", e)
		os.Exit(0)
	}
}

type Payload struct {
	Project string `json:"project"`
	Bom     string `json:"bom"`
}

type UploadResult struct {
	Token string `json:"token"`
}

type ProcessState struct {
	Processing bool `json:"processing"`
}

type ApiClient struct {
	ApiKey string
	ApiUrl string
}

func (apiClient ApiClient) Upload(inputFileName, projectId string) (uploadResult UploadResult, err error) {
	bomDataXml, err := ioutil.ReadFile(inputFileName)

	if err != nil {
		return
	}

	bomDataB64 := b64.StdEncoding.EncodeToString(bomDataXml)
	payload := Payload{Project: projectId, Bom: bomDataB64}
	payloadJson, err := json.Marshal(payload)

	if err != nil {
		return
	}

	client := apiClient.getHttpClient()
	req, err := http.NewRequest(http.MethodPut, apiClient.ApiUrl+BOM_UPLOAD_URL, bytes.NewBuffer(payloadJson))
	req.Header.Add("X-API-Key", apiClient.ApiKey)
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)

	if err != nil {
		return
	}

	defer resp.Body.Close()

	err = apiClient.checkRespStatusCode(resp.StatusCode)

	if err != nil {
		return
	}

	err = json.NewDecoder(resp.Body).Decode(&uploadResult)

	if err != nil {
		return
	}

	return uploadResult, nil
}

func (apiClient ApiClient) checkRespStatusCode(statusCode int) error {
	errorStatusCodes := map[int]string{
		404: "The project could not be found or invalid API URL.",
		401: "Authentication/Authorization error.",
		403: "Permission error. Check that you have all required permissions.",
	}

	if errorMsg, ok := errorStatusCodes[statusCode]; ok {
		return fmt.Errorf(errorMsg)
	}
	return nil
}

func (apiClient ApiClient) isTokenBeingProcessed(token string) (result bool, err error) {
	processState := ProcessState{}
	client := apiClient.getHttpClient()
	req, err := http.NewRequest(http.MethodGet, apiClient.ApiUrl+BOM_TOKEN_URL+"/"+token, nil)
	req.Header.Add("X-API-Key", apiClient.ApiKey)
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)

	if err != nil {
		return
	}

	defer resp.Body.Close()
	checkError(apiClient.checkRespStatusCode(resp.StatusCode))
	err = json.NewDecoder(resp.Body).Decode(&processState)

	if err != nil {
		return
	}

	if processState.Processing {
		return true, nil
	}

	return false, nil

}

func (apiClient ApiClient) getHttpClient() *http.Client {
	// Workaround for empty response body
	// See https://github.com/DependencyTrack/dependency-track/issues/474
	tr := &http.Transport{
		DisableCompression: true,
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr}
}

type Component struct {
	Uuid    string `json:"uuid"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Vulnerability struct {
	Uuid           string `json:"uuid"`
	VulnId         string `json:"vulnId"`
	Source         string `json:"source"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	Severity       string `json:"severity"`
	Recommendation string `json:"recommendation"`
}

type Analysis struct {
	AnalysisState string `json:"analysisState"`
}

type Finding struct {
	Comp   Component     `json:"component"`
	Vuln   Vulnerability `json:"vulnerability"`
	An     Analysis      `json:"analysis"`
	Matrix string        `json:"matrix"`
}

type Evaluator interface {
	Evaluate(f Finding) bool
}

type Gate struct {
	minimalSeverity string
}

func (g Gate) Evaluate(f Finding) bool {
	severityLevels := map[string]int{
		"CRITICAL":   0,
		"HIGH":       1,
		"MEDIUM":     2,
		"LOW":        3,
		"INFO":       4,
		"UNASSIGNED": 5,
	}

	sLevel, ok := severityLevels[strings.ToUpper(f.Vuln.Severity)]

	if ok == false {
		return false
	}

	minimalLevel, ok := severityLevels[strings.ToUpper(g.minimalSeverity)]

	// If no minimalLevel is specified then no filtering
	if ok == false {
		return true
	}

	if sLevel <= minimalLevel {
		return true
	}
	return false
}

func Filter(vs []Finding, f Evaluator) []Finding {
	result := make([]Finding, 0)
	for _, v := range vs {
		if f.Evaluate(v) {
			result = append(result, v)
		}
	}
	return result
}

func (apiClient ApiClient) GetFindings(projectId string, severityFilter string) (result []Finding, err error) {
	g := Gate{minimalSeverity: severityFilter}
	client := apiClient.getHttpClient()
	req, err := http.NewRequest(http.MethodGet, apiClient.ApiUrl+PROJECT_FINDINGS_URL+"/"+projectId, nil)
	req.Header.Add("X-API-Key", apiClient.ApiKey)
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)

	if err != nil {
		return
	}

	defer resp.Body.Close()
	checkError(apiClient.checkRespStatusCode(resp.StatusCode))
	err = json.NewDecoder(resp.Body).Decode(&result)
	result = Filter(result, g)
	if err != nil {
		return
	}
	return
}

func (apiClient ApiClient) PollTokenBeingProcessed(token string, timeout <-chan time.Time) error {
	time.Sleep(API_POLLING_STEP)
	for {
		select {
		case <-timeout:
			return nil
		default:
			state, err := apiClient.isTokenBeingProcessed(token)
			if err != nil {
				return err
			}
			if state == false {
				return nil
			}
			time.Sleep(API_POLLING_STEP)
		}
	}
	return nil
}

type Tag struct {
	Name string `json:"name"`
}

type Project struct {
	Uuid        string `json:"uuid"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Tags        []Tag  `json:"tags"`
}

type ProjectSearchResult struct {
	Project          Project
	VersionDifferent bool
}

func (apiClient ApiClient) LookupOrCreateProject(projectName, projectVersion string) (ProjectSearchResult, error) {

	result := ProjectSearchResult{}
	if projectName == "" {
		return result, errors.New("projectName is required")
	}

	//first lookup by project / version
	if projectVersion != "" {
		project, err := apiClient.findProjectByNameVersion(projectName, projectVersion)
		if err != nil {
			return result, err
		}
		if project.Uuid != "" {
			return ProjectSearchResult{
				Project:          project,
				VersionDifferent: false,
			}, nil
		}
	}

	project, err := apiClient.findProjectByName(projectName)
	if err != nil {
		return result, err
	}
	if project.Uuid != "" {
		return ProjectSearchResult{
			Project:          project,
			VersionDifferent: true,
		}, nil
	}

	//Unable to find project so time to create one
	projectId, err := apiClient.createProject(projectName, projectVersion)
	if err != nil {
		return result, err
	}
	if projectId != "" {
		return ProjectSearchResult{
			Project: Project{
				Name:    projectName,
				Uuid:    projectId,
				Version: projectVersion,
			},
			VersionDifferent: false,
		}, nil
	}

	return result, errors.New("unable to find or create project")
}

func (apiClient ApiClient) UpdateProjectVersion(projectID string, version string) error {
	client := apiClient.getHttpClient()
	payloadJson := []byte(fmt.Sprintf(`{"version": "%s"}`, version))

	req, err := http.NewRequest(http.MethodPatch, apiClient.ApiUrl+PROJECT_UPDATE_URL+"/"+projectID, bytes.NewBuffer(payloadJson))
	if err != nil {
		return err
	}
	req.Header.Add("X-API-Key", apiClient.ApiKey)
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)

	if err != nil {
		return err
	}
	defer resp.Body.Close()

	err = apiClient.checkRespStatusCode(resp.StatusCode)
	if err != nil {
		return err
	}
	return nil
}

func (apiClient ApiClient) findProjectByNameVersion(projectName, projectVersion string) (Project, error) {
	client := apiClient.getHttpClient()
	result := Project{}
	v := url.Values{}
	v.Set("name", projectName)
	v.Set("version", projectVersion)

	req, _ := http.NewRequest(http.MethodGet, apiClient.ApiUrl+PROJECT_LOOKUP_URL+"?"+v.Encode(), nil)
	req.Header.Add("X-API-Key", apiClient.ApiKey)
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return result, nil
	}

	err = apiClient.checkRespStatusCode(resp.StatusCode)
	if err != nil {
		return result, err
	}

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return result, err
	}
	return result, nil
}

func (apiClient ApiClient) findProjectByName(projectName string) (Project, error) {
	projects := []Project{}
	result := Project{}
	client := apiClient.getHttpClient()
	req, _ := http.NewRequest(http.MethodGet, apiClient.ApiUrl+PROJECT_ALL_URL+"?excludeInactive=true&pageSize=600&pageNumber=1", nil)
	req.Header.Add("X-API-Key", apiClient.ApiKey)
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()

	err = apiClient.checkRespStatusCode(resp.StatusCode)
	if err != nil {
		return result, err
	}
	err = json.NewDecoder(resp.Body).Decode(&projects)
	if err != nil {
		return result, err
	}

	for _, p := range projects {
		if strings.EqualFold(p.Name, projectName) {
			return p, nil
		}
	}
	return result, nil
}

func (apiClient ApiClient) createProject(projectName, projectVersion string) (projectId string, err error) {
	client := apiClient.getHttpClient()
	p := Project{Name: projectName, Version: projectVersion}
	result := Project{}
	payloadJson, err := json.Marshal(p)

	if err != nil {
		return
	}

	req, err := http.NewRequest(http.MethodPut, apiClient.ApiUrl+PROJECT_CREATE_URL, bytes.NewBuffer(payloadJson))
	req.Header.Add("X-API-Key", apiClient.ApiKey)
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)

	if err != nil {
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode == 201 {
		err = json.NewDecoder(resp.Body).Decode(&result)
		if err != nil {
			return
		}
		return result.Uuid, nil
	}

	err = apiClient.checkRespStatusCode(resp.StatusCode)

	if err != nil {
		return
	}

	return
}
