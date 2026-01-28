package ubuntuosv_test

import (
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	ubuntuosv "github.com/aquasecurity/trivy-db/pkg/vulnsrc/ubuntu-osv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

func TestVulnSrc_Update(t *testing.T) {
	tests := []struct {
		name       string
		dir        string
		wantValues []vulnsrctest.WantValues
		noBuckets  [][]string
		wantErr    string
	}{
		{
			name: "happy path",
			dir:  "testdata",
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{
						"data-source",
						"ubuntu 14.04",
					},
					Value: types.DataSource{
						ID:   vulnerability.Ubuntu,
						Name: "Ubuntu CVE Tracker",
						URL:  "https://git.launchpad.net/ubuntu-cve-tracker",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2025-0033",
						"ubuntu 14.04",
						"amd64-microcode",
					},
					Value: types.Advisory{
						VendorIDs: []string{
							"UBUNTU-CVE-2025-0033",
						},
						VulnerableVersions: []string{
							">=0",
						},
						PatchedVersions: []string{},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2025-0033",
						string(vulnerability.Ubuntu),
					},
					Value: types.VulnerabilityDetail{
						Description:  "Improper access control within AMD SEV-SNP could allow an admin privileged attacker to write to the RMP during SNP initialization, potentially resulting in a loss of SEV-SNP guest memory integrity.",
						CvssScoreV3:  6.0,
						CvssVectorV3: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:N",
						References: []string{
							"https://ubuntu.com/security/CVE-2025-0033",
							"https://www.cve.org/CVERecord?id=CVE-2025-0033",
							"https://www.amd.com/en/resources/product-security/bulletin/AMD-SB-3020.html",
						},
						PublishedDate:    utils.MustTimeParse("2025-10-14T15:16:00Z"),
						LastModifiedDate: utils.MustTimeParse("2025-11-27T05:17:43Z"),
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2025-0033",
					},
					Value: map[string]any{},
				},
			},
		},
		{
			name: "FIPS packages are skipped, regular packages are processed",
			dir:  "testdata",
			wantValues: []vulnsrctest.WantValues{
				// Data source for 20.04 (regular package)
				{
					Key: []string{
						"data-source",
						"ubuntu 20.04",
					},
					Value: types.DataSource{
						ID:   vulnerability.Ubuntu,
						Name: "Ubuntu CVE Tracker",
						URL:  "https://git.launchpad.net/ubuntu-cve-tracker",
					},
				},
				// Advisory for test-package (regular package) - should exist
				{
					Key: []string{
						"advisory-detail",
						"CVE-2024-FIPS-TEST",
						"ubuntu 20.04",
						"test-package",
					},
					Value: types.Advisory{
						VendorIDs: []string{
							"UBUNTU-CVE-2024-FIPS-TEST",
						},
						VulnerableVersions: []string{
							">=0",
						},
						PatchedVersions: []string{},
					},
				},
				// Vulnerability detail for CVE-2024-FIPS-TEST
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2024-FIPS-TEST",
						string(vulnerability.Ubuntu),
					},
					Value: types.VulnerabilityDetail{
						Description: "Test CVE with both FIPS and regular packages",
						References: []string{
							"https://ubuntu.com/security/CVE-2024-FIPS-TEST",
							"https://www.cve.org/CVERecord?id=CVE-2024-FIPS-TEST",
						},
						PublishedDate:    utils.MustTimeParse("2024-01-01T00:00:00Z"),
						LastModifiedDate: utils.MustTimeParse("2024-01-02T00:00:00Z"),
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2024-FIPS-TEST",
					},
					Value: map[string]any{},
				},
			},
		},
		{
			name: "ESM with non-ESM versions creates advisories for both",
			dir:  "testdata",
			wantValues: []vulnsrctest.WantValues{
				// Data source for 16.04-ESM
				{
					Key: []string{
						"data-source",
						"ubuntu 16.04-ESM",
					},
					Value: types.DataSource{
						ID:   vulnerability.Ubuntu,
						Name: "Ubuntu CVE Tracker",
						URL:  "https://git.launchpad.net/ubuntu-cve-tracker",
					},
				},
				// Data source for 16.04 (non-ESM, created by transformer)
				{
					Key: []string{
						"data-source",
						"ubuntu 16.04",
					},
					Value: types.DataSource{
						ID:   vulnerability.Ubuntu,
						Name: "Ubuntu CVE Tracker",
						URL:  "https://git.launchpad.net/ubuntu-cve-tracker",
					},
				},
				// Vulnerability detail should be created once
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2025-52881",
						string(vulnerability.Ubuntu),
					},
					Value: types.VulnerabilityDetail{
						Description:  "runc is a CLI tool for spawning and running containers according to the OCI specification. In versions 1.2.7, 1.3.2 and 1.4.0-rc.2, an attacker can trick runc into misdirecting writes to /proc to other procfs files through the use of a racing container with shared mounts (we have also verified this attack is possible to exploit using a standard Dockerfile with docker buildx build as that also permits triggering parallel execution of containers with custom shared mounts configured). This redirect could be through symbolic links in a tmpfs or theoretically other methods such as regular bind-mounts. While similar, the mitigation applied for the related CVE, CVE-2019-19921, was fairly limited and effectively only caused runc to verify that when LSM labels are written they are actually procfs files. This issue is fixed in versions 1.2.8, 1.3.3, and 1.4.0-rc.3.",
						CvssScoreV3:  7.6,
						CvssVectorV3: "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H",
						References: []string{
							"https://ubuntu.com/security/CVE-2025-52881",
							"https://www.cve.org/CVERecord?id=CVE-2025-52881",
							"https://github.com/opencontainers/runc/security/advisories/GHSA-cgrx-mc8f-2prm",
							"https://ubuntu.com/security/notices/USN-7851-1",
						},
						PublishedDate:    utils.MustTimeParse("2025-11-05T09:00:00Z"),
						LastModifiedDate: utils.MustTimeParse("2025-12-08T05:18:05Z"),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := ubuntuosv.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
				NoBuckets:  tt.noBuckets,
			})
		})
	}
}
