# dtrack-audit
[OWASP Dependency Track](https://dependencytrack.org) API client for your security CI/CD pipeline. See [Dependency-Track docs: Continuous Integration & Delivery](https://docs.dependencytrack.org/usage/cicd/) for use case.

## Install

### Local Installation

```bash
go get github.com/ozonru/dtrack-audit/cmd/dtrack-audit
```

## Features

* Fully configurable via environment variables
* Async and sync modes. In async mode dtrack-audit simply sends SBOM file to DTrack API (like cURL but *in much more comfortable way*). Sync mode means: upload SBOM file, wait for the scan result, show it and exit with non-zero code. So you can break corresponding CI/CD job to make developers pay attention to findings
* You can filter the results. With Sync mode enabled show result and fail an audit **if the results include a vulnerability with a severity of specified level or higher**. Severity levels are: critical, high, medium, low, info, unassigned
* Auto creation of projects. With this feautre you can configure SCA (with dtrack-audit) step globally for your CI/CD and it will create project, e.g. with name from environment variable like `$CI_PROJECT_NAME`. So you don't need to configure it manually for each project
* Support for TeamCity CI output. You can use `-T` flag to enable JSON output. After that, activate the [Golang build feature](https://www.jetbrains.com/help/teamcity/golang.html).

### Sample output

```bash
$ cyclonedx-bom -o bom.xml
$ dtrack-audit -s -g high

SBOM file is successfully uploaded to DTrack API. Result token is 12345f5e-4ccb-45fe-b8fd-1234a8bf0081

2 vulnerabilities found!

 > HIGH: Arbitrary File Write
   Component: adm-zip 0.4.7
   More info: https://dtrack/vulnerability/?source=NPM&vulnId=994

 > CRITICAL: Prototype Pollution
   Component: handlebars 4.0.11
   More info: https://dtrack/vulnerability/?source=NPM&vulnId=755
```
