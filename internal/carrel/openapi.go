package carrel

import _ "embed"

// openAPI describes the HTTP routes other than MCP (issue #556). A test fails
// when a route is registered without an entry here.
//
//go:embed openapi.json
var openAPI []byte
