package ubuntuosv

import (
	"strings"

	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

var (
	vulnsDir = "ubuntu-security-notices/cve"

	source = types.DataSource{
		ID:   vulnerability.Ubuntu,
		Name: "Ubuntu CVE Tracker",
		URL:  "https://git.launchpad.net/ubuntu-cve-tracker",
	}

	// errSkipped is returned when ecosystem should be skipped (not an actual error)
	errSkipped = oops.Errorf("skipped")
)

// resolveBucket creates an Ubuntu bucket from ecosystem string
// Examples:
// - "Ubuntu:14.04:LTS" -> ubuntu 14.04
// - "Ubuntu:Pro:16.04:LTS" -> ubuntu 16.04-ESM
// - "Ubuntu:20.04:LTS" -> ubuntu 20.04
// - "Ubuntu:25.10" -> ubuntu 25.10
// Note: FIPS ecosystems (e.g., "Ubuntu:Pro:FIPS:16.04:LTS") are not supported and will be skipped
func resolveBucket(suffix string) (bucket.Bucket, error) {
	// Split by colon to get parts
	// e.g. "14.04:LTS", "Pro:16.04:LTS", "25.10"
	parts := strings.Split(suffix, ":")

	var version string

	switch len(parts) {
	case 1, 2:
		// "25.10" or "14.04:LTS"
		version = parts[0]
	case 3:
		// "Pro:16.04:LTS" or "FIPS:16.04:LTS"
		modifier := strings.ToLower(parts[0])
		if modifier == "pro" {
			version = parts[1] + "-ESM"
		} else if strings.HasPrefix(modifier, "fips") {
			// Skip FIPS ecosystems (FIPS, FIPS-updates, FIPS-preview)
			return nil, errSkipped
		} else {
			return nil, oops.With("ecosystem", "ubuntu").With("suffix", suffix).Errorf("unsupported ecosystem format")
		}
	case 4:
		// "Pro:FIPS:16.04:LTS", "Pro:FIPS-updates:18.04:LTS"
		if strings.ToLower(parts[0]) == "pro" && strings.HasPrefix(strings.ToLower(parts[1]), "fips") {
			// Skip FIPS ecosystems
			return nil, errSkipped
		}
		return nil, oops.With("ecosystem", "ubuntu").With("suffix", suffix).Errorf("unsupported ecosystem format")
	default:
		return nil, oops.With("ecosystem", "ubuntu").With("suffix", suffix).Errorf("unsupported ecosystem format")
	}

	return newBucket(version, source), nil
}

type VulnSrc struct{}

func NewVulnSrc() VulnSrc {
	return VulnSrc{}
}

func (VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs VulnSrc) Update(root string) error {
	eb := oops.In("ubuntu-new").With("file_path", root)

	sources := map[ecosystem.Type]types.DataSource{
		ecosystem.Ubuntu: source,
	}

	if err := osv.New(vulnsDir, source.ID, sources,
		osv.WithBucketResolver("ubuntu", resolveBucket),
		osv.WithTransformer(&transformer{})).Update(root); err != nil {
		return eb.Wrapf(err, "failed to update Ubuntu vulnerability data")
	}

	return nil
}
