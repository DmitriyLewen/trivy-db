package ubuntu

import (
	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
)

// ubuntuBucket for Ubuntu ecosystem with DataSourceBucket support
type ubuntuBucket struct {
	base       bucket.Bucket
	dataSource types.DataSource
}

func (u ubuntuBucket) Name() string {
	return u.base.Name()
}

func (u ubuntuBucket) Ecosystem() ecosystem.Type {
	return u.base.Ecosystem()
}

func (u ubuntuBucket) DataSource() types.DataSource {
	return u.dataSource
}

// newBucket creates a bucket for Ubuntu ecosystem
func newBucket(version string, dataSource types.DataSource) bucket.Bucket {
	return ubuntuBucket{
		base:       bucket.NewUbuntu(version),
		dataSource: dataSource,
	}
}
