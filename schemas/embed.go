package schemas

import "embed"

// Files embeds the public AO Covenant JSON Schemas into the CLI binary.
//
//go:embed *.json
var Files embed.FS
