---
title: 		Release notes template
summary: 	This is the asset template file for Release Notes.  Be sure to remove all "!!! NOTE" entries.
---

# Release notes version 23.11 FP2 PP1

**Release date: 2024-08-09**

---

!!! disclaimer

    **IMPORTANT MESSAGE to products adopting this version of CSKM:** The HashiCorp Vault version within this CSKM release has shifted from MPL to a BSL License Model. It is the responsibility of each product team taking this release to Review the Announcement and Nokia Legal guidance for Impacts and Compliance Measures at the following: [LINK](https://web.yammer.com/main/org/nokia.com/threads/eyJfdHlwZSI6IlRocmVhZCIsImlkIjoiMjU2NjUyNjMzOTE2MjExMiJ9?trk_copy_link=V2)

## Software packages

| Release Type                          | Software                                                                                                                                                                                                                                                                                                                                                                                                            |
|---------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| RPMs                                  | <ul><li>[vault-1.17.1-1.x86_64.rpm](https://repo.cci.nokia.net/csf-yum-delivered/CSKM/1543/vault-1.17.1-1.x86_64.rpm) </li> <li>[skm-2.35.0-1.x86_64.rpm](https://repo.cci.nokia.net/csf-yum-delivered/CSKM/1543/skm-2.35.0-1.x86_64.rpm) </li> <li>[consul-template-0.19.4-0.x86_64.rpm](https://repo.cci.nokia.net/csf-yum-delivered/CSKM/consul-template-0.19.4-0.x86_64.rpm) </li></ul> |
| Docker                                | <ul><li>[skm-rocky8/2.35.1-1.620](https://repo.cci.nokia.net/csf-docker-delivered/cskm/skm-rocky8/2.35.1-1.620/) </li> <li>[skm-rocky9/2.35.1-1.277](https://repo.cci.nokia.net/csf-docker-delivered/cskm/skm-rocky9/2.35.1-1.277/)</li> </ul>  |
| Helm Chart                            | <ul><li>[cskm-8.2.1.tgz](https://repo.cci.nokia.net/csf-helm-stable/cskm-8.2.1.tgz) </li></ul>    |
| Ansible Playbook for RPM Installation | <ul><li>[cskm-ansible-2.35.0-1.tgz](https://repo.cci.nokia.net/csf-yum-delivered/CSKM/1543/cskm-ansible-2.35.0-1.tgz) </li></ul>   |
| CCTF Tests                            | <ul><li>[TP-cskm-2.35.0-1.tgz](https://repo.cci.nokia.net/csf-yum-delivered/CSKM/1543/TP-cskm-2.35.0-1.tgz) </li></ul> |
| Auto release scripts                  | <ul><li>[test-script-2.35.0.tgz](https://repo.cci.nokia.net/list/csf-yum-delivered/CSKM/1543/test-script-2.35.0.tgz) </li></ul>      |

### Software repo

| REPO    | Branch      | SHA1                                                                                                    | Tag   |
|---------|-------------|---------------------------------------------------------------------------------------------------------|-------|
| CSF-SKM | development | [7073f95cf8f746a39dfec64ed23b9807dc36367d](https://gerrit.ext.net.nokia.com/gerrit/c/CSF-SKM/+/7515506) | 23.11 FP2 PP1 |

### Configurable Images

#### cbur/cbur-agent

- Default Image Tag: 1.3.0-alpine-1338
- Security Scan: [Security Results](https://docs.ext.net.nokia.com/csf/lc/cbur/latest/releases/latest.html#security-testing-reports)
- TALKO: #[21547](https://talko.ext.net.nokia.com/certificates/details.php?certificate_id=21547)
- VAMS: [CBUR - Backup and Recovery container cbur-agent 23.11 FP2](https://vams.ext.net.nokia.com/)
- Instructions: Used for backup/restore, the functionality was enabled by default. Users could update according to its own requirement.

    ```yaml
    cbur:
      # cbura docker image
      _imageFlavorMapping:
        - flavor: &defaultCburImageFlavor "rocky8"
          tag: &defaultCburImageTag "1.3.0-alpine-1338"
          repository: &defaultCburImageRepo "cbur/cbur-agent"
    
        - flavor: "rocky9"
          tag: "1.3.0-alpine-1338"
          repository: "cbur/cbur-agent"
    
      # cbur pod image
        # This field points to the default value for imageFlavor.
      imageRepo:
      _imageRepo: *defaultCburImageRepo
      imageTag:
      _imageTag: *defaultCburImageTag
      imageFlavor:
      _imageFlavor: *defaultCburImageFlavor
      imageFlavorPolicy: "BestMatch"
    ```

#### tools/kubectl

- Default Image Tag: 1.28.12-rocky8-nano-20240801
- Security Scan: [Security Results](https://gitlabe2.ext.net.nokia.com/csf/os/ccbi/-/blob/master/attachments/ccbi-202408/kubectl-1.28.12-rocky8-nano-20240801.csv)
- TALKO: #[21868](https://talko.int.net.nokia.com/certificates/details.php?certificate_id=21868)
- VAMS: [docker image kubectl 1.28.12-rocky8-nano-20240801](https://vams.ext.net.nokia.com/)
- Instructions: Used for all helm jobs

    ```yaml
    kubectl:
      _imageFlavorMapping:
        - flavor: &defaultKubectlImageFlavor "rocky8"
          tag: &defaultKubectlImageTag "1.28.12-rocky8-nano-20240801"
          repository: &defaultKubectlImageRepo "tools/kubectl"
    
        - flavor: "rocky9"
          tag: "1.30.3-rocky9-nano-20240801"
          repository: "tools/kubectl"
    
      # kubectl pod image
        # This field points to the default value for imageFlavor.
      imageRepo:
      _imageRepo: *defaultKubectlImageRepo
      imageTag:
      _imageTag: *defaultKubectlImageTag
      imageFlavor:
      _imageFlavor: *defaultKubectlImageFlavor
      imageFlavorPolicy: "BestMatch"
    ```

#### keycloak/keycloak-py

- Default Image Tag: 1.1.4-rocky8-python3.11-3
- Security Scan: [Security Results](https://nokia.sharepoint.com/:x:/s/csf/domains/sec/EV7TcnNFWAFJk59xbpUdsTABreTiTIrgp26xd0egf9NVsA?e=62iScE)
- TALKO: [20807](https://talko.int.net.nokia.com/certificates/details.php?certificate_id=20807)
- VAMS: [CKEY 23.09 FP3 - Web SSO container Rocky8](https://vams.ext.net.nokia.com/)
- Instructions: Used for helm job. This job restarts CSKM pods if there are any changes to TLS certificates.

    ```yaml
    resourceWatcherJob: 
      # Resource watcher docker image
      _imageFlavorMapping:
        - flavor: &defaultKeycloakPyImageFlavor "rocky8"
          tag: &defaultKeycloakPyImageTag "1.1.4-rocky8-python3.11-3"
          repository: &defaultKeycloakPyImageRepo "keycloak/ckey-py"
    
        - flavor: "rocky9"
          tag: "1.1.4-rocky9-python3.11-3"
          repository: "keycloak/ckey-py"
    
      # Resource Watcher Job image
        # This field points to the default value for imageFlavor.
      imageRepo:
      _imageRepo: *defaultKeycloakPyImageRepo
      imageTag:
      _imageTag: *defaultKeycloakPyImageTag
      imageFlavor:
      _imageFlavor: *defaultKeycloakPyImageFlavor
      imageFlavorPolicy: "BestMatch"
    ```

## FOSS / Talko

- [HashiCorp Vault 1.17.1](https://github.com/hashicorp/vault/blob/main/CHANGELOG.md#1171)
- Certificate for CSKM 23.11 FP2 PP1 - Secret Key Management #[22242](https://talko.ext.net.nokia.com/certificates/details.php?certificate_id=22242)
- Certificate for CSKM 23.11 FP2 PP1 - Secret Key Management container Rocky8 #[22243](https://talko.ext.net.nokia.com/certificates/details.php?certificate_id=22243)
- Certificate for CSKM 23.11 FP2 PP1 - Secret Key Management container Rocky9 #[22244](https://talko.ext.net.nokia.com/certificates/details.php?certificate_id=22244)

## SVM / VAMS

Product:

```
CSF Components
```

Release name:

```
CSKM 23.11 FP2 PP1 - Secret Key Management container Rocky8
CSKM 23.11 FP2 PP1 - Secret Key Management container Rocky9

```

## Security testing

- [Security Testing plan](https://nokia.sharepoint.com/:w:/r/sites/csf/domains/sec/Shared%20Documents/CSF%20Catalog/CSKM/security/CSF_Security_Test_Plan_CSKM.docx?d=w7b093aba111a4b1080f23dc0ba10052b&csf=1&web=1&e=H7q6gj)
- Anchore Scans have been imported to VAMS
- Security Test results analysis
    - [Nessus local scan analysis](../guide/security/nessus_local_scans_rocky8.md)
    - [Nessus remote scan analysis](../guide/security/nessus_remote_scans_rocky8.md)

### Security testing reports

- Remote vulnerability and Port scan:
    - [jenkins_CSKM_23_11_FP2_rocky8_nessus_remote.pdf](https://nokia.sharepoint.com/:b:/s/csf/domains/sec/EQHrBAYCPNtLohTUPRxgnfEBC6EOeDE1Jju5ZVmQjQiHUQ?e=HUUoCC)
- Authenticated local vulnerability scan:
    - [jenkins_CSKM_23_11_FP2_Rocky8_nessus_local.pdf](https://nokia.sharepoint.com/:b:/s/csf/domains/sec/EVrVoapo6uJPhPAJLbu2DS0BtmcMr7PoNkDgtA6BYap9gg?e=ZPvQEq)
- Container vulnerability scan:
    - [23_11_FP2_CSKM_Rocky8_Docker_Anchore_Scans](https://nokia.sharepoint.com/:x:/r/sites/csf/domains/sec/_layouts/15/Doc.aspx?sourcedoc=%7BEFC510A4-E0D2-4AB1-BBE2-19B6189E6665%7D&file=CSKM_23_11_FP2_PP1_Rocky8_Anchore_Report.csv&action=default&mobileredirect=true)
    - [23_11_FP2_CSKM_Rocky9_Docker_Anchore_Scans](https://nokia.sharepoint.com/:x:/r/sites/csf/domains/sec/_layouts/15/Doc.aspx?sourcedoc=%7BEFC510A4-E0D2-4AB1-BBE2-19B6189E6665%7D&file=CSKM_23_11_FP2_PP1_Rocky8_Anchore_Report.csv&action=default&mobileredirect=true)
- Web application vulnerability scan: N/A
- Robustness testing: No security modifications for 23.11 FP2. [23.11FP2 HTTP-Server Suite](https://nokia.sharepoint.com/:u:/s/csf/domains/sec/ESHXfVT1xUJNuVKFYMCAqBwBvzVePgXDH4sR1CnowFTlxg?e=EblPmJ)
- DoS testing: No security modifications for 23.11 FP2. [23.11FP2 IPv4 Server Test suite](https://nokia.sharepoint.com/:u:/s/csf/domains/sec/EZ1uZR29WFhKo1uL3-QJNuwBLRzGWtFPJywWYI5lQlHfNQ?e=100ogR) [23.11FP2 TCP for IPv4 Server Test suite](https://nokia.sharepoint.com/:u:/s/csf/domains/sec/Eat_ExsjGsxHtKg5nqr8isEBDBZ8BbfCugRYUr69FwpdkA?e=A8QUQj)
- Malware scan: No issues found
- DB security testing: N/A
- Static code analysis: [Sonarqube Analysis](https://sonarqube.int.net.nokia.com/dashboard?id=com.nokia.aa.csf%3ACSF-SKM) - No new issues found
- CIS Hardening benchmark: -

## Deployment model

- Bare metal: Supported
- Container (CNF): Supported

## Compatibility

### Required

- Rocky: 8.10, 9
- Base image: rocky8-python311-nano:3.11.7-20240604, rocky9-python311-nano:3.11.7-20240627
- kubectl docker image: 1.28.12-rocky8-nano-20240801, 1.30.3-rocky9-nano-20240801
- cbur-agent image: 1.3.0-alpine-1338
- Java: N/A
- Python: 3.11.7
- Network support: IPv4, IPv6, Dual-Stack
- Helm best practices: 3.9.0
- Helm plugins: backup - 3.2.12, heal- 3.0.10, restore - 3.2.10, scale - 3.0.27
- Istio: 1.18.2, 1.19.4, 1.20.3
- RedHat Service Mesh: - 2.5.2
- Horizontal Pod Autoscaling: N/A

### AnyCloud

- Amazon EKS: 1.23, 1.24, 1.25, 1.26, 1.27, 1.28, 1.29, 1.30
- Azure Kubernetes Service: 1.27, 1.28, 1.29
- Google Kubernetes Engine: 1.27, 1.28, 1.29
- Nokia Container Services: 20FP2, 22, 22.7, 22.12, 23.10, 24.7 P7
- RedHat OpenShift: 4.12, 4.13, 4.14, 4.15
- VMware Tanzu Kubernetes Grid: 2.1, 2.4, 2.5

### Other

- CMDB: 23.09 FP2 PP3
- CBUR: 23.11 FP1 PP1
- CLOG: 23.09 FP3

## Resolved issues

### Features / Bug Fixes

| JIRA                                                                  | Description                                                                          |
|-----------------------------------------------------------------------|--------------------------------------------------------------------------------------|
| [CSFSEC-10242](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-10242) | Base_OS update to 3.11.9-20240801 and packages update                                |
| [CSFSEC-10287](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-10287) | Disable audit log listener, if audit_logging is disabled                             |
| [CSFSEC-10388](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-10388) | Backup pvc needs to be created only if cbur is enabled                               |

### Fixed CVEs

- [CVE-2024-28182](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-9762)
- [CVE-2024-2961](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-9763)
- [CVE-2024-29018](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-9764)
- [CVE-2024-28180](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-9765)
- [CVE-2024-24786](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-9768)
- [CVE-2023-2953](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-9834)
- [CVE-2024-2877](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-9835)
- [SVM-115476](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-7480)
- [SVM-127389](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-8257)
- [CVE-2023-38545,CVE-2023-38546](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-8322)
- [CVE-2023-46218,CVE-2023-46219](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-9008)
- [CVE-2023-28322,CVE-2023-46218](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-9272)
- [CVE-2024-28834](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-9672)
- [CVE-2024-26256](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-9863)
- [CVE-2024-2660](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-9719)
- [GHSA-9763-4f94-gfch](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-9185)
- [CVE-2023-6004,CVE-2023-6918,CVE-2023-48795](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-9114)
- [CVE-2024-22365](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-9149)
- [CVE-2023-45288](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-9755)
- [CVE-2024-33602](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-9757)
- [CVE-2024-33601](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-9758)
- [CVE-2024-33600](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-9759)
- [GHSA-7jwh-3vrq-q3m8](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-9760)

## Breaking Changes

- None

## Known issues and limitations

### Limitations

CSKM does not support Horizontal Pod Autoscaling and Active-Active Georedundancy.<a href="https://csf.gitlabe2-pages.ext.net.nokia.com/sec/cskm/latest/guide/faq/faq.html"> Please refer FAQ section for more info.</a>

### Known CVEs

- [CVE-2014-3566](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-8425)
- [CVE-2023-45918](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-9504)
- [CVE-2024-2398](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-9671)
- [CVE-2024-2236](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-9862)
- [CVE-2024-34459](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-9898)
- [CVE-2024-0406](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-9756)

## Test results

- CSKM 23.11 FP2 PP1 - Helm and RPM Testing.
- All failed test cases have been tested manually. No issues observed.

### Anycloud Test results

- Tested on multiple anycloud and NCS clusters - OCP-4.15, EKS-1.30, NCS 23.10 and NCS 24.7
- [CSKM-23.11FP2 PP1 XRAY TEST PLAN](https://jiradc2.ext.net.nokia.com/browse/CSFSEC-10391)

### Performance measurement

- Performance Test with **Min Load** - CMDB. CSKM resource limits (memory: 125Mi, cpu: 100m)
    - [Results](https://nokia.sharepoint.com/:u:/s/csf/domains/sec/EWUvyU4Pw85EnHd5PpgfR4MBDZdu6yeSTGdKFBXwszpULw?e=svHwwI)
    - [Build](https://build8.cci.nokia.net/job/CTO/job/CSF/job/Security/job/CSF-SECURITY-TEST-NEW/job/CSF-CSKM-TESTS/job/CSF-CSKM-NEW/4231/)

- Performance Test with **full load** - CMDB and Raft Backend. CSKM resource limits (memory: 1024Mi, cpu: 1024m)
    - [Results](https://nokia.sharepoint.com/:u:/s/csf/domains/sec/Edi_BKtqDPZDvgZHUwCehY8B3xily1bbBIPVnOMOTs5dPA?e=4YzbvQ)
    - [Build](https://build8.cci.nokia.net/job/CTO/job/CSF/job/Security/job/CSF-SECURITY-TEST-NEW/job/CSF-CSKM-TESTS/job/CSF-CSKM-NEW/4234/)

- Custom Perf Test with **100req/sec load** - CMDB Backend. CSKM resource limits (memory: 512Mi, cpu: 200m)
    - [Results](https://build8.cci.nokia.net/job/CTO/job/CSF/job/Security/job/CSF-SECURITY-TEST-NEW/job/CSF-CSKM-TESTS/job/CSF-CSKM-NEW/4220/console)
    - [Build](https://build8.cci.nokia.net/job/CTO/job/CSF/job/Security/job/CSF-SECURITY-TEST-NEW/job/CSF-CSKM-TESTS/job/CSF-CSKM-NEW/4220)

- [CSF-RESOURCE-FOOTPRINT](pm_cskm_23.11_FP2.yaml)

### RPM Test results

- [RPM TESTS](https://nokia.sharepoint.com/:t:/s/csf/domains/sec/Ed-Amr2_kmlHsps30Ok6TUsBgNeZo_cuLhYBGHjF_8wuoQ?e=5VXf1p)
- Upgrade/Rollback to 23.11 FP2 tested manually for RPMs

### LCM event time measurements

- [LCM Events Execution Time](https://nokia.sharepoint.com/:x:/s/csf/domains/sec/EU9o_ggH2SVCrXzIdAXfLMUBlFGUFcnweMVaBRRcliR3-g?e=kLaglt)

## Interface changes

Values changes

```yaml
global:
  keepImmutableSecret: False

  istio:
    version: "1.6"
    enabled: False
    mtls:
      enabled: True
      mode: "STRICT"

cskm:
  useServiceAccountVolumeProjection: true
  tokenExpirationSeconds: 3600

istio:
  version:
  enabled:
  mtls:
    enabled:
    mode:
```

### API / CLI

- No changes

### Alarms

### SDC

- No changes
