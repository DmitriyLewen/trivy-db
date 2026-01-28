package ubuntu_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/ubuntu"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

func TestVulnSrc_Update(t *testing.T) {
	vs := ubuntu.NewVulnSrc()
	vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
		Dir: "testdata",
		WantValues: []vulnsrctest.WantValues{
			// CVE-2022-2068: Tests FIPS skip and Pro→ESM without fixed version
			{
				Key: []string{"data-source", "ubuntu 16.04-ESM"},
				Value: types.DataSource{
					ID:   vulnerability.Ubuntu,
					Name: "Ubuntu CVE Tracker",
					URL:  "https://github.com/canonical/ubuntu-security-notices",
				},
			},
			{
				Key: []string{"data-source", "ubuntu 16.04"},
				Value: types.DataSource{
					ID:   vulnerability.Ubuntu,
					Name: "Ubuntu CVE Tracker",
					URL:  "https://github.com/canonical/ubuntu-security-notices",
				},
			},
			{
				Key: []string{"advisory-detail", "CVE-2022-2068", "ubuntu 16.04-ESM", "edk2"},
				Value: types.Advisory{
					VendorIDs:          []string{"UBUNTU-CVE-2022-2068"},
					VulnerableVersions: []string{">=0"},
					PatchedVersions:    []string{},
				},
			},
			{
				Key: []string{"advisory-detail", "CVE-2022-2068", "ubuntu 16.04", "edk2"},
				Value: types.Advisory{
					VendorIDs:          []string{"UBUNTU-CVE-2022-2068"},
					VulnerableVersions: []string{">=0"},
					PatchedVersions:    []string{},
				},
			},
			{
				Key: []string{"vulnerability-detail", "CVE-2022-2068", string(vulnerability.Ubuntu)},
				Value: types.VulnerabilityDetail{
					Severity:     types.SeverityMedium,
					Description:  "In addition to the c_rehash shell command injection identified in CVE-2022-1292, further circumstances where the c_rehash script does not properly sanitise shell metacharacters to prevent command injection were found by code review. When the CVE-2022-1292 was fixed it was not discovered that there are other places in the script where the file names of certificates being hashed were possibly passed to a command executed through the shell. This script is distributed by some operating systems in a manner where it is automatically executed. On such operating systems, an attacker could execute arbitrary commands with the privileges of the script. Use of the c_rehash script is considered obsolete and should be replaced by the OpenSSL rehash command line tool. Fixed in OpenSSL 3.0.4 (Affected 3.0.0,3.0.1,3.0.2,3.0.3). Fixed in OpenSSL 1.1.1p (Affected 1.1.1-1.1.1o). Fixed in OpenSSL 1.0.2zf (Affected 1.0.2-1.0.2ze).",
					CvssScoreV3:  9.8,
					CvssVectorV3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					References: []string{
						"https://ubuntu.com/security/CVE-2022-2068",
						"https://www.openssl.org/news/secadv/20220621.txt",
						"https://ubuntu.com/security/notices/USN-5488-1",
						"https://ubuntu.com/security/notices/USN-5488-2",
						"https://ubuntu.com/security/notices/USN-6457-1",
						"https://www.cve.org/CVERecord?id=CVE-2022-2068",
						"https://ubuntu.com/security/notices/USN-7018-1",
					},
					PublishedDate:    utils.MustTimeParse("2022-06-21T00:00:00Z"),
					LastModifiedDate: utils.MustTimeParse("2025-09-08T16:49:35Z"),
				},
			},
			{
				Key:   []string{"vulnerability-id", "CVE-2022-2068"},
				Value: map[string]any{},
			},

			// CVE-2025-58056: Tests Pro→ESM with fixed version
			{
				Key: []string{"advisory-detail", "CVE-2025-58056", "ubuntu 16.04-ESM", "netty"},
				Value: types.Advisory{
					VendorIDs:          []string{"UBUNTU-CVE-2025-58056"},
					VulnerableVersions: []string{"<1:4.0.34-1ubuntu0.1~esm3"},
					PatchedVersions:    []string{"1:4.0.34-1ubuntu0.1~esm3"},
				},
			},
			{
				Key: []string{"advisory-detail", "CVE-2025-58056", "ubuntu 16.04", "netty"},
				Value: types.Advisory{
					VendorIDs:          []string{"UBUNTU-CVE-2025-58056"},
					VulnerableVersions: []string{"<1:4.0.34-1ubuntu0.1~esm3"},
					PatchedVersions:    []string{"1:4.0.34-1ubuntu0.1~esm3"},
				},
			},
			{
				Key: []string{"vulnerability-detail", "CVE-2025-58056", string(vulnerability.Ubuntu)},
				Value: types.VulnerabilityDetail{
					Severity:     types.SeverityLow,
					Description:  "Netty is an asynchronous event-driven network application framework for development of maintainable high performance protocol servers and clients. In versions 4.1.124.Final, and 4.2.0.Alpha3 through 4.2.4.Final, Netty incorrectly accepts standalone newline characters (LF) as a chunk-size line terminator, regardless of a preceding carriage return (CR), instead of requiring CRLF per HTTP/1.1 standards. When combined with reverse proxies that parse LF differently (treating it as part of the chunk extension), attackers can craft requests that the proxy sees as one request but Netty processes as two, enabling request smuggling attacks. This is fixed in versions 4.1.125.Final and 4.2.5.Final.",
					CvssScoreV3:  7.5,
					CvssVectorV3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
					References: []string{
						"https://ubuntu.com/security/CVE-2025-58056",
						"https://www.cve.org/CVERecord?id=CVE-2025-58056",
						"https://datatracker.ietf.org/doc/html/rfc9112#name-chunked-transfer-coding",
						"https://github.com/JLLeitschuh/unCVEed/issues/1",
						"https://github.com/netty/netty/commit/edb55fd8e0a3bcbd85881e423464f585183d1284",
						"https://github.com/netty/netty/issues/15522",
						"https://github.com/netty/netty/pull/15611",
						"https://github.com/netty/netty/security/advisories/GHSA-fghv-69vj-qj49",
						"https://w4ke.info/2025/06/18/funky-chunks.html",
						"https://ubuntu.com/security/notices/USN-7918-1",
					},
					PublishedDate:    utils.MustTimeParse("2025-09-03T21:15:00Z"),
					LastModifiedDate: utils.MustTimeParse("2025-12-10T05:27:21Z"),
				},
			},
			{
				Key:   []string{"vulnerability-id", "CVE-2025-58056"},
				Value: map[string]any{},
			},
		},
	})
}

func TestResolveBucket(t *testing.T) {
	tests := []struct {
		name     string
		suffix   string
		wantName string
		wantErr  bool
	}{
		{
			name:     "simple version",
			suffix:   "25.10",
			wantName: "ubuntu 25.10",
		},
		{
			name:     "version with LTS",
			suffix:   "14.04:LTS",
			wantName: "ubuntu 14.04",
		},
		{
			name:     "version with LTS 20.04",
			suffix:   "20.04:LTS",
			wantName: "ubuntu 20.04",
		},
		{
			name:     "Pro converts to ESM",
			suffix:   "Pro:16.04:LTS",
			wantName: "ubuntu 16.04-ESM",
		},
		{
			name:     "Pro with 18.04",
			suffix:   "Pro:18.04:LTS",
			wantName: "ubuntu 18.04-ESM",
		},
		{
			name:    "FIPS is skipped",
			suffix:  "FIPS:16.04:LTS",
			wantErr: true,
		},
		{
			name:    "FIPS-updates is skipped",
			suffix:  "FIPS-updates:18.04:LTS",
			wantErr: true,
		},
		{
			name:    "FIPS-preview is skipped",
			suffix:  "FIPS-preview:20.04:LTS",
			wantErr: true,
		},
		{
			name:    "Pro:FIPS is skipped",
			suffix:  "Pro:FIPS:16.04:LTS",
			wantErr: true,
		},
		{
			name:    "Pro:FIPS-updates is skipped",
			suffix:  "Pro:FIPS-updates:18.04:LTS",
			wantErr: true,
		},
		{
			name:     "unknown 3-part modifier uses second part as version",
			suffix:   "Unknown:16.04:LTS",
			wantName: "ubuntu 16.04",
		},
		{
			name:     "Pro Realtime Kernel converts to ESM",
			suffix:   "Pro:22.04:LTS:Realtime:Kernel",
			wantName: "ubuntu 22.04-ESM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bucket, err := ubuntu.ResolveBucket(tt.suffix)

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, bucket)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, bucket)
			assert.Equal(t, tt.wantName, bucket.Name())
		})
	}
}
