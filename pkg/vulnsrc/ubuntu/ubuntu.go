package ubuntu

import (
	"strings"

	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

var (
	vulnsDir = "ubuntu-security-notices/osv/cve"

	source = types.DataSource{
		ID:   vulnerability.Ubuntu,
		Name: "Ubuntu CVE Tracker",
		URL:  "https://github.com/canonical/ubuntu-security-notices",
	}

	// errSkipped is returned when ecosystem should be skipped (not an actual error)
	errSkipped = oops.Errorf("skipped")
)

// resolveBucket creates an Ubuntu bucket from ecosystem string
// Examples:
// - "Ubuntu:14.04:LTS" -> ubuntu 14.04
// - "Ubuntu:Pro:16.04:LTS" -> ubuntu 16.04-ESM
// - "Ubuntu:Pro:22.04:LTS:Realtime:Kernel" -> ubuntu 22.04-ESM
// - "Ubuntu:20.04:LTS" -> ubuntu 20.04
// - "Ubuntu:25.10" -> ubuntu 25.10
// - "Ubuntu:22.04:LTS:for:NVIDIA:BlueField" -> ubuntu 22.04
// Note: FIPS ecosystems (e.g., "Ubuntu:Pro:FIPS:16.04:LTS") are not supported and will be skipped
// TODO simplify logic??? check parts with `.`.
func resolveBucket(suffix string) (bucket.Bucket, error) {
	// Split by colon to get parts
	// e.g. "14.04:LTS", "Pro:16.04:LTS", "25.10"
	parts := strings.Split(strings.ToLower(suffix), ":")

	// "25.10" or "14.04:LTS"
	if len(parts) <= 2 {
		return newBucket(parts[0], source), nil
	}

	// Skip FIPS ecosystems (check first two parts for "fips")
	// e.g. "FIPS:16.04:LTS", "FIPS-updates:18.04:LTS", "Pro:FIPS:16.04:LTS"
	if strings.HasPrefix(parts[0], "fips") || strings.HasPrefix(parts[1], "fips") {
		return nil, errSkipped
	}

	// If parts[0] is a version (contains "."), use it directly
	// e.g. "22.04:LTS:for:NVIDIA:BlueField" -> ubuntu 22.04
	if strings.Contains(parts[0], ".") {
		return newBucket(parts[0], source), nil
	}

	// "Pro:16.04:LTS", "Pro:22.04:LTS:Realtime:Kernel", etc.
	version := parts[1]
	if parts[0] == "pro" {
		version += "-ESM"
	}

	return newBucket(version, source), nil
}

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
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

func (vs VulnSrc) Get(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In("ubuntu").With("release", params.Release).With("package_name", params.PkgName)
	bucketName := bucket.NewUbuntu(params.Release).Name()
	advisories, err := vs.dbc.GetAdvisories(bucketName, params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
	}
	return advisories, nil
}
