package buildinfo

import "runtime"

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

const VersionResultSchemaVersion = "covenant.version-result.v1"

type Info struct {
	SchemaVersion string `json:"schema_version"`
	Version       string `json:"version"`
	Commit        string `json:"commit"`
	Date          string `json:"date"`
	GoVersion     string `json:"go_version"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
}

func Current() Info {
	return Info{
		SchemaVersion: VersionResultSchemaVersion,
		Version:       Version,
		Commit:        Commit,
		Date:          Date,
		GoVersion:     runtime.Version(),
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
	}
}
