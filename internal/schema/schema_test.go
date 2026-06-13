package schema

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"

	embedded "github.com/uesugitorachiyo/ao-covenant/schemas"
)

func schemaTestPath(fileName string) string {
	return "schemas/" + fileName
}

func TestRequiredSchemasExistAndMatchIDs(t *testing.T) {
	if err := ValidateRegistry(); err != nil {
		t.Fatalf("ValidateRegistry returned error: %v", err)
	}
}

func TestCatalogListsRequiredSchemasInStableOrder(t *testing.T) {
	catalog := Catalog()

	required := RequiredFiles()
	if len(catalog) != len(required) {
		t.Fatalf("catalog len = %d, want %d", len(catalog), len(required))
	}
	for index, entry := range catalog {
		if entry.ID != required[index].ID || entry.FileName != required[index].FileName {
			t.Fatalf("catalog[%d] = %+v, want id %s file %s", index, entry, required[index].ID, required[index].FileName)
		}
		if entry.SchemaPath != schemaTestPath(required[index].FileName) {
			t.Fatalf("catalog[%d].SchemaPath = %q, want schemas/%s", index, entry.SchemaPath, required[index].FileName)
		}
	}

	catalog[0].ID = "mutated"
	if Catalog()[0].ID == "mutated" {
		t.Fatalf("Catalog returned mutable backing storage")
	}
}

func TestKnownSchemaIDRecognizesCatalogEntries(t *testing.T) {
	if !KnownSchemaID(ContractSchemaID) {
		t.Fatalf("KnownSchemaID(%q) = false, want true", ContractSchemaID)
	}
	if KnownSchemaID("covenant.unknown.v1") {
		t.Fatalf("KnownSchemaID accepted unknown schema")
	}
}

func TestRequiredSchemaLookupReturnsStableMetadata(t *testing.T) {
	required, ok := RequiredSchemaByID(VersionResultSchemaID)
	if !ok {
		t.Fatalf("RequiredSchemaByID(%q) ok = false, want true", VersionResultSchemaID)
	}
	if required.ID != VersionResultSchemaID {
		t.Fatalf("lookup ID = %q, want %q", required.ID, VersionResultSchemaID)
	}
	if required.FileName != "covenant.version-result.v1.schema.json" {
		t.Fatalf("lookup file = %q", required.FileName)
	}
	if required.SchemaPath != schemaTestPath("covenant.version-result.v1.schema.json") {
		t.Fatalf("lookup schema path = %q", required.SchemaPath)
	}
}

func TestRequiredSchemaLookupRejectsUnknownSchema(t *testing.T) {
	if required, ok := RequiredSchemaByID("covenant.missing.v1"); ok {
		t.Fatalf("RequiredSchemaByID accepted unknown schema: %+v", required)
	}
}

func TestRequiredSchemasReturnsCallerSafeCopy(t *testing.T) {
	required := RequiredSchemas()
	if len(required) == 0 {
		t.Fatalf("RequiredSchemas returned no entries")
	}
	required[0].ID = "mutated"
	required[0].FileName = "mutated.schema.json"
	required[0].SchemaPath = "mutated/path"

	fresh := RequiredSchemas()
	if fresh[0].ID == "mutated" || fresh[0].FileName == "mutated.schema.json" || fresh[0].SchemaPath == "mutated/path" {
		t.Fatalf("RequiredSchemas returned mutable backing storage")
	}
}

func TestValidateRegistryAcceptsPublishedSchemas(t *testing.T) {
	if err := ValidateRegistry(); err != nil {
		t.Fatalf("ValidateRegistry returned error: %v", err)
	}
}

func TestValidateRequiredSchemasRejectsDuplicateMetadata(t *testing.T) {
	required := RequiredSchemas()
	required = append(required, RequiredSchema{
		FileName:   required[0].FileName,
		ID:         required[0].ID,
		SchemaPath: required[0].SchemaPath,
	})

	err := validateRequiredSchemas(required, embeddedSchemaFiles(t))
	if err == nil {
		t.Fatalf("validateRequiredSchemas returned nil error for duplicate metadata")
	}
	message := err.Error()
	for _, want := range []string{"duplicate schema id", "duplicate schema file", "duplicate schema path"} {
		if !strings.Contains(message, want) {
			t.Fatalf("error %q missing %q", message, want)
		}
	}
}

func TestValidateRequiredSchemasRejectsSchemaPathDrift(t *testing.T) {
	required := RequiredSchemas()
	required[0].SchemaPath = "schemas/moved.schema.json"

	err := validateRequiredSchemas(required, embeddedSchemaFiles(t))
	if err == nil {
		t.Fatalf("validateRequiredSchemas returned nil error for schema path drift")
	}
	if !strings.Contains(err.Error(), "schema path") {
		t.Fatalf("error %q missing schema path context", err)
	}
}

func TestValidateRequiredSchemasRejectsSchemaIDNamingDrift(t *testing.T) {
	required := []RequiredSchema{{
		FileName:   "covenant.Bad_Name.v1.schema.json",
		ID:         "covenant.Bad_Name.v1",
		SchemaPath: "schemas/covenant.Bad_Name.v1.schema.json",
	}}
	files := []string{"covenant.Bad_Name.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.Bad_Name.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$id": "covenant.Bad_Name.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.Bad_Name.v1" }
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for schema id naming drift")
	}
	if !strings.Contains(err.Error(), "schema id") || !strings.Contains(err.Error(), "lowercase") {
		t.Fatalf("error %q missing schema id naming context", err)
	}
}

func TestValidateRequiredSchemasRejectsSchemaFileNameDrift(t *testing.T) {
	required := []RequiredSchema{{
		FileName:   "covenant.registry-file-name.v1.schema.json",
		ID:         "covenant.registry-name.v1",
		SchemaPath: "schemas/covenant.registry-file-name.v1.schema.json",
	}}
	files := []string{"covenant.registry-file-name.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.registry-file-name.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$id": "covenant.registry-name.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.registry-name.v1" }
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for schema filename drift")
	}
	if !strings.Contains(err.Error(), "schema file") || !strings.Contains(err.Error(), "covenant.registry-name.v1.schema.json") {
		t.Fatalf("error %q missing schema filename naming context", err)
	}
}

func TestValidateRequiredSchemasRejectsMissingSchemaDraftDeclaration(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.missing-draft.v1.schema.json", "covenant.missing-draft.v1")}
	files := []string{"covenant.missing-draft.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.missing-draft.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$id": "covenant.missing-draft.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.missing-draft.v1" }
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for missing $schema draft declaration")
	}
	if !strings.Contains(err.Error(), "$schema") || !strings.Contains(err.Error(), "draft/2020-12") {
		t.Fatalf("error %q missing draft declaration context", err)
	}
}

func TestValidateRequiredSchemasRejectsMismatchedSchemaDraftDeclaration(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.old-draft.v1.schema.json", "covenant.old-draft.v1")}
	files := []string{"covenant.old-draft.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.old-draft.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"$id": "covenant.old-draft.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.old-draft.v1" }
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for mismatched $schema draft declaration")
	}
	if !strings.Contains(err.Error(), "$schema") || !strings.Contains(err.Error(), "http://json-schema.org/draft-07/schema#") {
		t.Fatalf("error %q missing mismatched draft declaration context", err)
	}
}

func TestValidateRequiredSchemasRejectsRequiredFieldWithoutProperty(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.missing-required-property.v1.schema.json", "covenant.missing-required-property.v1")}
	files := []string{"covenant.missing-required-property.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.missing-required-property.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.missing-required-property.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version", "name"],
			"properties": {
				"schema_version": { "const": "covenant.missing-required-property.v1" }
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for required field without property")
	}
	if !strings.Contains(err.Error(), "required field") || !strings.Contains(err.Error(), "name") || !strings.Contains(err.Error(), "#") {
		t.Fatalf("error %q missing required property context", err)
	}
}

func TestValidateRequiredSchemasRejectsNestedRequiredFieldWithoutProperty(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.nested-missing-required-property.v1.schema.json", "covenant.nested-missing-required-property.v1")}
	files := []string{"covenant.nested-missing-required-property.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.nested-missing-required-property.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.nested-missing-required-property.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version", "items"],
			"properties": {
				"schema_version": { "const": "covenant.nested-missing-required-property.v1" },
				"items": {
					"type": "array",
					"items": {
						"type": "object",
						"additionalProperties": false,
						"required": ["digest"],
						"properties": {
							"path": { "type": "string" }
						}
					}
				}
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for nested required field without property")
	}
	if !strings.Contains(err.Error(), "required field") || !strings.Contains(err.Error(), "digest") || !strings.Contains(err.Error(), "#/properties/items/items") {
		t.Fatalf("error %q missing nested required property context", err)
	}
}

func TestValidateRequiredSchemasRejectsRequiredKeywordWithoutProperties(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.required-without-properties.v1.schema.json", "covenant.required-without-properties.v1")}
	files := []string{"covenant.required-without-properties.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.required-without-properties.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.required-without-properties.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"]
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for required keyword without properties")
	}
	if !strings.Contains(err.Error(), "required keyword") || !strings.Contains(err.Error(), "properties object") || !strings.Contains(err.Error(), "#") {
		t.Fatalf("error %q missing required keyword properties context", err)
	}
}

func TestValidateRequiredSchemasRejectsNonArrayRequiredKeyword(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.non-array-required.v1.schema.json", "covenant.non-array-required.v1")}
	files := []string{"covenant.non-array-required.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.non-array-required.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.non-array-required.v1",
			"type": "object",
			"additionalProperties": false,
			"required": "schema_version",
			"properties": {
				"schema_version": { "const": "covenant.non-array-required.v1" }
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for non-array required keyword")
	}
	if !strings.Contains(err.Error(), "required keyword") || !strings.Contains(err.Error(), "array of strings") {
		t.Fatalf("error %q missing required keyword array context", err)
	}
}

func TestValidateRequiredSchemasRejectsNonStringRequiredField(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.non-string-required.v1.schema.json", "covenant.non-string-required.v1")}
	files := []string{"covenant.non-string-required.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.non-string-required.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.non-string-required.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version", 7],
			"properties": {
				"schema_version": { "const": "covenant.non-string-required.v1" }
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for non-string required entry")
	}
	if !strings.Contains(err.Error(), "required keyword") || !strings.Contains(err.Error(), "array of strings") {
		t.Fatalf("error %q missing required keyword string entry context", err)
	}
}

func TestValidateRequiredSchemasRejectsNonObjectPropertiesKeyword(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.non-object-properties.v1.schema.json", "covenant.non-object-properties.v1")}
	files := []string{"covenant.non-object-properties.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.non-object-properties.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.non-object-properties.v1",
			"type": "object",
			"additionalProperties": false,
			"properties": "schema_version"
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for non-object properties keyword")
	}
	if !strings.Contains(err.Error(), "properties keyword") || !strings.Contains(err.Error(), "object") || !strings.Contains(err.Error(), "#") {
		t.Fatalf("error %q missing properties keyword object context", err)
	}
}

func TestValidateRequiredSchemasRejectsNonSchemaPropertyDefinition(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.non-schema-property.v1.schema.json", "covenant.non-schema-property.v1")}
	files := []string{"covenant.non-schema-property.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.non-schema-property.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.non-schema-property.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.non-schema-property.v1" },
				"name": "string"
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for non-schema property definition")
	}
	if !strings.Contains(err.Error(), "property definition") || !strings.Contains(err.Error(), "name") || !strings.Contains(err.Error(), "#/properties/name") {
		t.Fatalf("error %q missing property definition context", err)
	}
}

func TestValidateRequiredSchemasAcceptsBooleanPropertySchemas(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.boolean-property-schema.v1.schema.json", "covenant.boolean-property-schema.v1")}
	files := []string{"covenant.boolean-property-schema.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.boolean-property-schema.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.boolean-property-schema.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.boolean-property-schema.v1" },
				"disabled": false,
				"anything": true
			}
		}`)},
	}

	if err := validateRequiredSchemasWithFS(required, files, schemas); err != nil {
		t.Fatalf("validateRequiredSchemasWithFS returned error for boolean property schemas: %v", err)
	}
}

func TestValidateRequiredSchemasRejectsNonObjectPatternPropertiesKeyword(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.non-object-pattern-properties.v1.schema.json", "covenant.non-object-pattern-properties.v1")}
	files := []string{"covenant.non-object-pattern-properties.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.non-object-pattern-properties.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.non-object-pattern-properties.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.non-object-pattern-properties.v1" }
			},
			"patternProperties": "^x-"
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for non-object patternProperties keyword")
	}
	if !strings.Contains(err.Error(), "patternProperties keyword") || !strings.Contains(err.Error(), "object") || !strings.Contains(err.Error(), "#") {
		t.Fatalf("error %q missing patternProperties keyword object context", err)
	}
}

func TestValidateRequiredSchemasRejectsInvalidPatternPropertiesPattern(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.invalid-pattern-property.v1.schema.json", "covenant.invalid-pattern-property.v1")}
	files := []string{"covenant.invalid-pattern-property.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.invalid-pattern-property.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.invalid-pattern-property.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.invalid-pattern-property.v1" }
			},
			"patternProperties": {
				"^[": { "type": "string" }
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for invalid patternProperties pattern")
	}
	if !strings.Contains(err.Error(), "patternProperties pattern") || !strings.Contains(err.Error(), "^[") || !strings.Contains(err.Error(), "#/patternProperties/^[") {
		t.Fatalf("error %q missing patternProperties pattern context", err)
	}
}

func TestValidateRequiredSchemasRejectsNonSchemaPatternPropertyDefinition(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.non-schema-pattern-property.v1.schema.json", "covenant.non-schema-pattern-property.v1")}
	files := []string{"covenant.non-schema-pattern-property.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.non-schema-pattern-property.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.non-schema-pattern-property.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.non-schema-pattern-property.v1" }
			},
			"patternProperties": {
				"^x-": "string"
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for non-schema pattern property definition")
	}
	if !strings.Contains(err.Error(), "patternProperties definition") || !strings.Contains(err.Error(), "^x-") || !strings.Contains(err.Error(), "#/patternProperties/^x-") {
		t.Fatalf("error %q missing patternProperties definition context", err)
	}
}

func TestValidateRequiredSchemasAcceptsBooleanPatternPropertySchemas(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.boolean-pattern-property-schema.v1.schema.json", "covenant.boolean-pattern-property-schema.v1")}
	files := []string{"covenant.boolean-pattern-property-schema.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.boolean-pattern-property-schema.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.boolean-pattern-property-schema.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.boolean-pattern-property-schema.v1" }
			},
			"patternProperties": {
				"^disabled$": false,
				"^x-": true
			}
		}`)},
	}

	if err := validateRequiredSchemasWithFS(required, files, schemas); err != nil {
		t.Fatalf("validateRequiredSchemasWithFS returned error for boolean pattern property schemas: %v", err)
	}
}

func TestValidateRequiredSchemasRejectsNonSchemaAdditionalPropertiesKeyword(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.non-schema-additional-properties.v1.schema.json", "covenant.non-schema-additional-properties.v1")}
	files := []string{"covenant.non-schema-additional-properties.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.non-schema-additional-properties.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.non-schema-additional-properties.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version", "nested"],
			"properties": {
				"schema_version": { "const": "covenant.non-schema-additional-properties.v1" },
				"nested": {
					"type": "object",
					"additionalProperties": "string"
				}
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for non-schema additionalProperties keyword")
	}
	if !strings.Contains(err.Error(), "additionalProperties keyword") || !strings.Contains(err.Error(), "schema object or boolean") || !strings.Contains(err.Error(), "#/properties/nested/additionalProperties") {
		t.Fatalf("error %q missing additionalProperties keyword context", err)
	}
}

func TestValidateRequiredSchemasRejectsNonSchemaUnevaluatedPropertiesKeyword(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.non-schema-unevaluated-properties.v1.schema.json", "covenant.non-schema-unevaluated-properties.v1")}
	files := []string{"covenant.non-schema-unevaluated-properties.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.non-schema-unevaluated-properties.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.non-schema-unevaluated-properties.v1",
			"type": "object",
			"unevaluatedProperties": false,
			"required": ["schema_version", "nested"],
			"properties": {
				"schema_version": { "const": "covenant.non-schema-unevaluated-properties.v1" },
				"nested": {
					"type": "object",
					"unevaluatedProperties": ["blocked"]
				}
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for non-schema unevaluatedProperties keyword")
	}
	if !strings.Contains(err.Error(), "unevaluatedProperties keyword") || !strings.Contains(err.Error(), "schema object or boolean") || !strings.Contains(err.Error(), "#/properties/nested/unevaluatedProperties") {
		t.Fatalf("error %q missing unevaluatedProperties keyword context", err)
	}
}

func TestValidateRequiredSchemasAcceptsBooleanPropertyBoundarySchemas(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.boolean-boundary-schema.v1.schema.json", "covenant.boolean-boundary-schema.v1")}
	files := []string{"covenant.boolean-boundary-schema.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.boolean-boundary-schema.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.boolean-boundary-schema.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version", "nested"],
			"properties": {
				"schema_version": { "const": "covenant.boolean-boundary-schema.v1" },
				"nested": {
					"type": "object",
					"additionalProperties": true,
					"unevaluatedProperties": false
				}
			}
		}`)},
	}

	if err := validateRequiredSchemasWithFS(required, files, schemas); err != nil {
		t.Fatalf("validateRequiredSchemasWithFS returned error for boolean property boundary schemas: %v", err)
	}
}

func TestValidateRequiredSchemasRejectsNonSchemaItemsKeyword(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.non-schema-items.v1.schema.json", "covenant.non-schema-items.v1")}
	files := []string{"covenant.non-schema-items.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.non-schema-items.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.non-schema-items.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version", "entries"],
			"properties": {
				"schema_version": { "const": "covenant.non-schema-items.v1" },
				"entries": {
					"type": "array",
					"items": "string"
				}
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for non-schema items keyword")
	}
	if !strings.Contains(err.Error(), "items keyword") || !strings.Contains(err.Error(), "schema object or boolean") || !strings.Contains(err.Error(), "#/properties/entries/items") {
		t.Fatalf("error %q missing items keyword context", err)
	}
}

func TestValidateRequiredSchemasRejectsNonSchemaContainsKeyword(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.non-schema-contains.v1.schema.json", "covenant.non-schema-contains.v1")}
	files := []string{"covenant.non-schema-contains.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.non-schema-contains.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.non-schema-contains.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version", "entries"],
			"properties": {
				"schema_version": { "const": "covenant.non-schema-contains.v1" },
				"entries": {
					"type": "array",
					"contains": ["string"]
				}
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for non-schema contains keyword")
	}
	if !strings.Contains(err.Error(), "contains keyword") || !strings.Contains(err.Error(), "schema object or boolean") || !strings.Contains(err.Error(), "#/properties/entries/contains") {
		t.Fatalf("error %q missing contains keyword context", err)
	}
}

func TestValidateRequiredSchemasRejectsNonArrayPrefixItemsKeyword(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.non-array-prefix-items.v1.schema.json", "covenant.non-array-prefix-items.v1")}
	files := []string{"covenant.non-array-prefix-items.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.non-array-prefix-items.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.non-array-prefix-items.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version", "tuple"],
			"properties": {
				"schema_version": { "const": "covenant.non-array-prefix-items.v1" },
				"tuple": {
					"type": "array",
					"prefixItems": { "type": "string" }
				}
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for non-array prefixItems keyword")
	}
	if !strings.Contains(err.Error(), "prefixItems keyword") || !strings.Contains(err.Error(), "array") || !strings.Contains(err.Error(), "#/properties/tuple/prefixItems") {
		t.Fatalf("error %q missing prefixItems keyword context", err)
	}
}

func TestValidateRequiredSchemasRejectsNonSchemaPrefixItemsEntry(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.non-schema-prefix-items-entry.v1.schema.json", "covenant.non-schema-prefix-items-entry.v1")}
	files := []string{"covenant.non-schema-prefix-items-entry.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.non-schema-prefix-items-entry.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.non-schema-prefix-items-entry.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version", "tuple"],
			"properties": {
				"schema_version": { "const": "covenant.non-schema-prefix-items-entry.v1" },
				"tuple": {
					"type": "array",
					"prefixItems": [
						{ "type": "string" },
						"number"
					]
				}
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for non-schema prefixItems entry")
	}
	if !strings.Contains(err.Error(), "prefixItems entry") || !strings.Contains(err.Error(), "schema object or boolean") || !strings.Contains(err.Error(), "#/properties/tuple/prefixItems/1") {
		t.Fatalf("error %q missing prefixItems entry context", err)
	}
}

func TestValidateRequiredSchemasAcceptsBooleanArrayItemSchemas(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.boolean-array-item-schema.v1.schema.json", "covenant.boolean-array-item-schema.v1")}
	files := []string{"covenant.boolean-array-item-schema.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.boolean-array-item-schema.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.boolean-array-item-schema.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version", "entries"],
			"properties": {
				"schema_version": { "const": "covenant.boolean-array-item-schema.v1" },
				"entries": {
					"type": "array",
					"prefixItems": [true, false],
					"items": false,
					"contains": true,
					"unevaluatedItems": false
				}
			}
		}`)},
	}

	if err := validateRequiredSchemasWithFS(required, files, schemas); err != nil {
		t.Fatalf("validateRequiredSchemasWithFS returned error for boolean array item schemas: %v", err)
	}
}

func TestValidateRequiredSchemasRejectsNonArrayAllOfKeyword(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.non-array-all-of.v1.schema.json", "covenant.non-array-all-of.v1")}
	files := []string{"covenant.non-array-all-of.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.non-array-all-of.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.non-array-all-of.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.non-array-all-of.v1" }
			},
			"allOf": { "type": "object" }
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for non-array allOf keyword")
	}
	if !strings.Contains(err.Error(), "allOf keyword") || !strings.Contains(err.Error(), "non-empty array") || !strings.Contains(err.Error(), "#/allOf") {
		t.Fatalf("error %q missing allOf keyword context", err)
	}
}

func TestValidateRequiredSchemasRejectsEmptyAnyOfKeyword(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.empty-any-of.v1.schema.json", "covenant.empty-any-of.v1")}
	files := []string{"covenant.empty-any-of.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.empty-any-of.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.empty-any-of.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.empty-any-of.v1" }
			},
			"anyOf": []
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for empty anyOf keyword")
	}
	if !strings.Contains(err.Error(), "anyOf keyword") || !strings.Contains(err.Error(), "non-empty array") || !strings.Contains(err.Error(), "#/anyOf") {
		t.Fatalf("error %q missing anyOf keyword context", err)
	}
}

func TestValidateRequiredSchemasRejectsNonSchemaOneOfEntry(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.non-schema-one-of-entry.v1.schema.json", "covenant.non-schema-one-of-entry.v1")}
	files := []string{"covenant.non-schema-one-of-entry.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.non-schema-one-of-entry.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.non-schema-one-of-entry.v1",
			"type": "object",
			"unevaluatedProperties": false,
			"oneOf": [
				{ "type": "object" },
				"object"
			]
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for non-schema oneOf entry")
	}
	if !strings.Contains(err.Error(), "oneOf entry") || !strings.Contains(err.Error(), "schema object or boolean") || !strings.Contains(err.Error(), "#/oneOf/1") {
		t.Fatalf("error %q missing oneOf entry context", err)
	}
}

func TestValidateRequiredSchemasRejectsNonSchemaNotKeyword(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.non-schema-not.v1.schema.json", "covenant.non-schema-not.v1")}
	files := []string{"covenant.non-schema-not.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.non-schema-not.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.non-schema-not.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.non-schema-not.v1" }
			},
			"not": ["object"]
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for non-schema not keyword")
	}
	if !strings.Contains(err.Error(), "not keyword") || !strings.Contains(err.Error(), "schema object or boolean") || !strings.Contains(err.Error(), "#/not") {
		t.Fatalf("error %q missing not keyword context", err)
	}
}

func TestValidateRequiredSchemasAcceptsBooleanCompositionSchemas(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.boolean-composition-schema.v1.schema.json", "covenant.boolean-composition-schema.v1")}
	files := []string{"covenant.boolean-composition-schema.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.boolean-composition-schema.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.boolean-composition-schema.v1",
			"type": "object",
			"unevaluatedProperties": false,
			"oneOf": [true, false],
			"allOf": [true],
			"anyOf": [true, false],
			"not": false
		}`)},
	}

	if err := validateRequiredSchemasWithFS(required, files, schemas); err != nil {
		t.Fatalf("validateRequiredSchemasWithFS returned error for boolean composition schemas: %v", err)
	}
}

func TestValidateRequiredSchemasRejectsNonSchemaIfKeyword(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.non-schema-if.v1.schema.json", "covenant.non-schema-if.v1")}
	files := []string{"covenant.non-schema-if.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.non-schema-if.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.non-schema-if.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.non-schema-if.v1" }
			},
			"if": "object",
			"then": { "required": ["name"] }
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for non-schema if keyword")
	}
	if !strings.Contains(err.Error(), "if keyword") || !strings.Contains(err.Error(), "schema object or boolean") || !strings.Contains(err.Error(), "#/if") {
		t.Fatalf("error %q missing if keyword context", err)
	}
}

func TestValidateRequiredSchemasRejectsNonSchemaThenKeyword(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.non-schema-then.v1.schema.json", "covenant.non-schema-then.v1")}
	files := []string{"covenant.non-schema-then.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.non-schema-then.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.non-schema-then.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.non-schema-then.v1" }
			},
			"if": { "properties": { "kind": { "const": "named" } } },
			"then": ["name"]
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for non-schema then keyword")
	}
	if !strings.Contains(err.Error(), "then keyword") || !strings.Contains(err.Error(), "schema object or boolean") || !strings.Contains(err.Error(), "#/then") {
		t.Fatalf("error %q missing then keyword context", err)
	}
}

func TestValidateRequiredSchemasRejectsNonSchemaElseKeyword(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.non-schema-else.v1.schema.json", "covenant.non-schema-else.v1")}
	files := []string{"covenant.non-schema-else.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.non-schema-else.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.non-schema-else.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.non-schema-else.v1" }
			},
			"if": { "properties": { "kind": { "const": "named" } } },
			"else": "blocked"
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for non-schema else keyword")
	}
	if !strings.Contains(err.Error(), "else keyword") || !strings.Contains(err.Error(), "schema object or boolean") || !strings.Contains(err.Error(), "#/else") {
		t.Fatalf("error %q missing else keyword context", err)
	}
}

func TestValidateRequiredSchemasAcceptsBooleanConditionalSchemas(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.boolean-conditional-schema.v1.schema.json", "covenant.boolean-conditional-schema.v1")}
	files := []string{"covenant.boolean-conditional-schema.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.boolean-conditional-schema.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.boolean-conditional-schema.v1",
			"type": "object",
			"unevaluatedProperties": false,
			"if": true,
			"then": false,
			"else": true
		}`)},
	}

	if err := validateRequiredSchemasWithFS(required, files, schemas); err != nil {
		t.Fatalf("validateRequiredSchemasWithFS returned error for boolean conditional schemas: %v", err)
	}
}

func TestValidateRequiredSchemasRejectsNonStringPatternKeyword(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.non-string-pattern.v1.schema.json", "covenant.non-string-pattern.v1")}
	files := []string{"covenant.non-string-pattern.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.non-string-pattern.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.non-string-pattern.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.non-string-pattern.v1" },
				"name": { "type": "string", "pattern": 7 }
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for non-string pattern keyword")
	}
	if !strings.Contains(err.Error(), "pattern keyword") || !strings.Contains(err.Error(), "must be a string") || !strings.Contains(err.Error(), "#/properties/name/pattern") {
		t.Fatalf("error %q missing pattern keyword context", err)
	}
}

func TestValidateRequiredSchemasRejectsInvalidPatternKeyword(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.invalid-pattern.v1.schema.json", "covenant.invalid-pattern.v1")}
	files := []string{"covenant.invalid-pattern.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.invalid-pattern.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.invalid-pattern.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.invalid-pattern.v1" },
				"name": { "type": "string", "pattern": "[" }
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for invalid pattern keyword")
	}
	if !strings.Contains(err.Error(), "pattern keyword") || !strings.Contains(err.Error(), "must compile as ECMA regex") || !strings.Contains(err.Error(), "#/properties/name/pattern") {
		t.Fatalf("error %q missing invalid pattern context", err)
	}
}

func TestValidateRequiredSchemasRejectsNonStringFormatKeyword(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.non-string-format.v1.schema.json", "covenant.non-string-format.v1")}
	files := []string{"covenant.non-string-format.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.non-string-format.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.non-string-format.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.non-string-format.v1" },
				"created_at": { "type": "string", "format": 42 }
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for non-string format keyword")
	}
	if !strings.Contains(err.Error(), "format keyword") || !strings.Contains(err.Error(), "must be a non-empty string") || !strings.Contains(err.Error(), "#/properties/created_at/format") {
		t.Fatalf("error %q missing format keyword context", err)
	}
}

func TestValidateRequiredSchemasRejectsInvalidStringLengthKeywords(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.invalid-string-lengths.v1.schema.json", "covenant.invalid-string-lengths.v1")}
	files := []string{"covenant.invalid-string-lengths.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.invalid-string-lengths.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.invalid-string-lengths.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.invalid-string-lengths.v1" },
				"short_name": { "type": "string", "minLength": -1 },
				"long_name": { "type": "string", "maxLength": 1.5 }
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for invalid string length keywords")
	}
	if !strings.Contains(err.Error(), "minLength keyword") || !strings.Contains(err.Error(), "#/properties/short_name/minLength") {
		t.Fatalf("error %q missing minLength keyword context", err)
	}
	if !strings.Contains(err.Error(), "maxLength keyword") || !strings.Contains(err.Error(), "#/properties/long_name/maxLength") {
		t.Fatalf("error %q missing maxLength keyword context", err)
	}
	if !strings.Contains(err.Error(), "non-negative integer") {
		t.Fatalf("error %q missing string length rule context", err)
	}
}

func TestValidateRequiredSchemasRejectsNonNumberNumericBoundaryKeywords(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.non-number-bounds.v1.schema.json", "covenant.non-number-bounds.v1")}
	files := []string{"covenant.non-number-bounds.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.non-number-bounds.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.non-number-bounds.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.non-number-bounds.v1" },
				"low": { "type": "number", "minimum": "0" },
				"high": { "type": "number", "maximum": true },
				"after": { "type": "number", "exclusiveMinimum": [] },
				"before": { "type": "number", "exclusiveMaximum": {} }
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for non-number numeric boundary keywords")
	}
	for _, want := range []string{
		"minimum keyword",
		"#/properties/low/minimum",
		"maximum keyword",
		"#/properties/high/maximum",
		"exclusiveMinimum keyword",
		"#/properties/after/exclusiveMinimum",
		"exclusiveMaximum keyword",
		"#/properties/before/exclusiveMaximum",
		"must be a number",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err, want)
		}
	}
}

func TestValidateRequiredSchemasRejectsInvalidMultipleOfKeyword(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.invalid-multiple-of.v1.schema.json", "covenant.invalid-multiple-of.v1")}
	files := []string{"covenant.invalid-multiple-of.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.invalid-multiple-of.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.invalid-multiple-of.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.invalid-multiple-of.v1" },
				"zero": { "type": "integer", "multipleOf": 0 },
				"negative": { "type": "number", "multipleOf": -1 },
				"text": { "type": "number", "multipleOf": "2" }
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for invalid multipleOf keyword")
	}
	for _, want := range []string{
		"multipleOf keyword",
		"#/properties/zero/multipleOf",
		"#/properties/negative/multipleOf",
		"#/properties/text/multipleOf",
		"must be a number greater than zero",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err, want)
		}
	}
}

func TestValidateRequiredSchemasRejectsInvalidTypeKeyword(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.invalid-type-keyword.v1.schema.json", "covenant.invalid-type-keyword.v1")}
	files := []string{"covenant.invalid-type-keyword.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.invalid-type-keyword.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.invalid-type-keyword.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.invalid-type-keyword.v1" },
				"empty": { "type": [] },
				"bad": { "type": "text" },
				"mixed": { "type": ["string", 7] },
				"duplicate": { "type": ["string", "string"] }
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for invalid type keyword")
	}
	for _, want := range []string{
		"type keyword",
		"#/properties/empty/type",
		"#/properties/bad/type",
		"#/properties/mixed/type/1",
		"#/properties/duplicate/type/1",
		"must be one of",
		"must not contain duplicates",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err, want)
		}
	}
}

func TestValidateRequiredSchemasAcceptsTypeKeywordUnion(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.valid-type-union.v1.schema.json", "covenant.valid-type-union.v1")}
	files := []string{"covenant.valid-type-union.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.valid-type-union.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.valid-type-union.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.valid-type-union.v1" },
				"nullable": { "type": ["string", "null"] }
			}
		}`)},
	}

	if err := validateRequiredSchemasWithFS(required, files, schemas); err != nil {
		t.Fatalf("validateRequiredSchemasWithFS returned error for valid type union: %v", err)
	}
}

func TestValidateRequiredSchemasRejectsInvalidEnumKeyword(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.invalid-enum-keyword.v1.schema.json", "covenant.invalid-enum-keyword.v1")}
	files := []string{"covenant.invalid-enum-keyword.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.invalid-enum-keyword.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.invalid-enum-keyword.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.invalid-enum-keyword.v1" },
				"empty": { "type": "string", "enum": [] },
				"text": { "type": "string", "enum": "open" },
				"duplicate": { "type": "string", "enum": ["open", "open"] }
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for invalid enum keyword")
	}
	for _, want := range []string{
		"enum keyword",
		"#/properties/empty/enum",
		"#/properties/text/enum",
		"#/properties/duplicate/enum/1",
		"non-empty array",
		"must not contain duplicate values",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err, want)
		}
	}
}

func TestValidateRequiredSchemasRejectsConstKeywordThatDoesNotMatchType(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.mismatched-const-type.v1.schema.json", "covenant.mismatched-const-type.v1")}
	files := []string{"covenant.mismatched-const-type.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.mismatched-const-type.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.mismatched-const-type.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.mismatched-const-type.v1" },
				"bad": { "type": "string", "const": null },
				"wrong": { "type": ["string", "null"], "const": 42 }
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for const keyword that does not match type")
	}
	for _, want := range []string{
		"const keyword",
		"#/properties/bad/const",
		"#/properties/wrong/const",
		"must match the sibling type keyword",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err, want)
		}
	}
}

func TestValidateRequiredSchemasRejectsUnregisteredEmbeddedSchema(t *testing.T) {
	files := append(embeddedSchemaFiles(t), "covenant.unregistered.v1.schema.json")

	err := validateRequiredSchemas(RequiredSchemas(), files)
	if err == nil {
		t.Fatalf("validateRequiredSchemas returned nil error for unregistered embedded schema")
	}
	if !strings.Contains(err.Error(), "unregistered embedded schema") {
		t.Fatalf("error %q missing unregistered embedded schema context", err)
	}
}

func TestValidateRequiredSchemasRejectsMismatchedEmbeddedID(t *testing.T) {
	required := RequiredSchemas()
	required[0].ID = "covenant.mismatched.v1"

	err := validateRequiredSchemas(required, embeddedSchemaFiles(t))
	if err == nil {
		t.Fatalf("validateRequiredSchemas returned nil error for mismatched schema id")
	}
	if !strings.Contains(err.Error(), "$id") {
		t.Fatalf("error %q missing $id context", err)
	}
}

func TestValidateRequiredSchemasAcceptsRootUnevaluatedPropertiesFalse(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.composed.v1.schema.json", "covenant.composed.v1")}
	files := []string{"covenant.composed.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.composed.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.composed.v1",
			"type": "object",
			"unevaluatedProperties": false,
			"oneOf": [
				{ "$ref": "#/$defs/report" }
			],
			"$defs": {
				"report": {
					"type": "object",
					"additionalProperties": false,
					"required": ["schema_version"],
					"properties": {
						"schema_version": { "const": "covenant.composed.v1" }
					}
				}
			}
		}`)},
	}

	if err := validateRequiredSchemasWithFS(required, files, schemas); err != nil {
		t.Fatalf("validateRequiredSchemasWithFS returned error: %v", err)
	}
}

func TestValidateRequiredSchemasRejectsMissingRootAdditionalPropertiesFalse(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.loose.v1.schema.json", "covenant.loose.v1")}
	files := []string{"covenant.loose.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.loose.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$id": "covenant.loose.v1",
			"type": "object",
			"properties": {
				"schema_version": { "const": "covenant.loose.v1" }
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for loose root schema")
	}
	if !strings.Contains(err.Error(), "additionalProperties") {
		t.Fatalf("error %q missing additionalProperties context", err)
	}
}

func TestValidateRequiredSchemasRejectsPermissiveRootAdditionalProperties(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.permissive.v1.schema.json", "covenant.permissive.v1")}
	files := []string{"covenant.permissive.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.permissive.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$id": "covenant.permissive.v1",
			"type": "object",
			"additionalProperties": true,
			"properties": {
				"schema_version": { "const": "covenant.permissive.v1" }
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for permissive root schema")
	}
	if !strings.Contains(err.Error(), "additionalProperties") {
		t.Fatalf("error %q missing additionalProperties context", err)
	}
}

func TestValidateRequiredSchemasRejectsMissingLocalRefTarget(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.broken-local-ref.v1.schema.json", "covenant.broken-local-ref.v1")}
	files := []string{"covenant.broken-local-ref.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.broken-local-ref.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$id": "covenant.broken-local-ref.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version", "task"],
			"properties": {
				"schema_version": { "const": "covenant.broken-local-ref.v1" },
				"task": { "$ref": "#/$defs/missing_task" }
			},
			"$defs": {
				"present_task": {
					"type": "string",
					"minLength": 1
				}
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for missing local $ref target")
	}
	if !strings.Contains(err.Error(), "unresolved local $ref") || !strings.Contains(err.Error(), "#/$defs/missing_task") {
		t.Fatalf("error %q missing local $ref context", err)
	}
}

func TestValidateRequiredSchemasRejectsUnregisteredExternalRef(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.broken-external-ref.v1.schema.json", "covenant.broken-external-ref.v1")}
	files := []string{"covenant.broken-external-ref.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.broken-external-ref.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$id": "covenant.broken-external-ref.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version", "task"],
			"properties": {
				"schema_version": { "const": "covenant.broken-external-ref.v1" },
				"task": { "$ref": "covenant.missing-task.v1" }
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for unregistered external $ref")
	}
	if !strings.Contains(err.Error(), "unregistered external $ref") || !strings.Contains(err.Error(), "covenant.missing-task.v1") {
		t.Fatalf("error %q missing external $ref context", err)
	}
}

func TestValidateRequiredSchemasAcceptsRegisteredExternalRef(t *testing.T) {
	required := []RequiredSchema{
		requiredSchema("covenant.ref-owner.v1.schema.json", "covenant.ref-owner.v1"),
		requiredSchema("covenant.ref-target.v1.schema.json", "covenant.ref-target.v1"),
	}
	files := []string{"covenant.ref-owner.v1.schema.json", "covenant.ref-target.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.ref-owner.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.ref-owner.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version", "target"],
			"properties": {
				"schema_version": { "const": "covenant.ref-owner.v1" },
				"target": { "$ref": "covenant.ref-target.v1" }
			}
		}`)},
		"covenant.ref-target.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.ref-target.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version", "name"],
			"properties": {
				"schema_version": { "const": "covenant.ref-target.v1" },
				"name": { "type": "string", "minLength": 1 }
			}
		}`)},
	}

	if err := validateRequiredSchemasWithFS(required, files, schemas); err != nil {
		t.Fatalf("validateRequiredSchemasWithFS returned error: %v", err)
	}
}

func TestValidateRequiredSchemasRejectsMissingSchemaVersionRequirement(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.missing-schema-version.v1.schema.json", "covenant.missing-schema-version.v1")}
	files := []string{"covenant.missing-schema-version.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.missing-schema-version.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$id": "covenant.missing-schema-version.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["name"],
			"properties": {
				"schema_version": { "const": "covenant.missing-schema-version.v1" },
				"name": { "type": "string", "minLength": 1 }
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for missing schema_version requirement")
	}
	if !strings.Contains(err.Error(), "schema_version") || !strings.Contains(err.Error(), "required") {
		t.Fatalf("error %q missing schema_version requirement context", err)
	}
}

func TestValidateRequiredSchemasRejectsMismatchedSchemaVersionConst(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.mismatched-schema-version.v1.schema.json", "covenant.mismatched-schema-version.v1")}
	files := []string{"covenant.mismatched-schema-version.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.mismatched-schema-version.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$id": "covenant.mismatched-schema-version.v1",
			"type": "object",
			"additionalProperties": false,
			"required": ["schema_version"],
			"properties": {
				"schema_version": { "const": "covenant.other.v1" }
			}
		}`)},
	}

	err := validateRequiredSchemasWithFS(required, files, schemas)
	if err == nil {
		t.Fatalf("validateRequiredSchemasWithFS returned nil error for mismatched schema_version const")
	}
	if !strings.Contains(err.Error(), "schema_version const") || !strings.Contains(err.Error(), "covenant.other.v1") {
		t.Fatalf("error %q missing schema_version const context", err)
	}
}

func TestValidateRequiredSchemasAcceptsComposedSchemaVersionRequirement(t *testing.T) {
	required := []RequiredSchema{requiredSchema("covenant.composed-schema-version.v1.schema.json", "covenant.composed-schema-version.v1")}
	files := []string{"covenant.composed-schema-version.v1.schema.json"}
	schemas := fstest.MapFS{
		"covenant.composed-schema-version.v1.schema.json": &fstest.MapFile{Data: []byte(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": "covenant.composed-schema-version.v1",
			"type": "object",
			"unevaluatedProperties": false,
			"oneOf": [
				{ "$ref": "#/$defs/single" },
				{ "$ref": "#/$defs/batch" }
			],
			"$defs": {
				"single": {
					"type": "object",
					"additionalProperties": false,
					"required": ["schema_version"],
					"properties": {
						"schema_version": { "const": "covenant.composed-schema-version.v1" }
					}
				},
				"batch": {
					"type": "object",
					"additionalProperties": false,
					"required": ["schema_version", "items"],
					"properties": {
						"schema_version": { "const": "covenant.composed-schema-version.v1" },
						"items": { "type": "array" }
					}
				}
			}
		}`)},
	}

	if err := validateRequiredSchemasWithFS(required, files, schemas); err != nil {
		t.Fatalf("validateRequiredSchemasWithFS returned error: %v", err)
	}
}

func embeddedSchemaFiles(t *testing.T) []string {
	t.Helper()
	entries, err := embedded.Files.ReadDir(".")
	if err != nil {
		t.Fatalf("read embedded schemas: %v", err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".schema.json") {
			continue
		}
		files = append(files, entry.Name())
	}
	return files
}

func TestWriteJSONFileValidatesCreatesParentAndPreservesMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "version.json")
	value := map[string]any{
		"schema_version": VersionResultSchemaID,
		"version":        "dev",
		"commit":         "unknown",
		"date":           "unknown",
		"go_version":     "go1.test",
		"os":             "testos",
		"arch":           "testarch",
	}

	if err := WriteJSONFile(path, VersionResultSchemaID, value, 0o640); err != nil {
		t.Fatalf("WriteJSONFile returned error: %v", err)
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	if !strings.HasSuffix(string(bytes), "\n") {
		t.Fatalf("written JSON missing trailing newline: %q", string(bytes))
	}
	if err := ValidateBytes(VersionResultSchemaID, bytes); err != nil {
		t.Fatalf("written JSON did not validate: %v\njson:\n%s", err, string(bytes))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat written file: %v", err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Fatalf("file mode = %o, want 0640", got)
	}
}

func TestWriteJSONFileRejectsInvalidSchemaValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid.json")
	value := map[string]any{
		"schema_version": VersionResultSchemaID,
		"version":        "",
	}

	err := WriteJSONFile(path, VersionResultSchemaID, value, 0o644)
	if err == nil {
		t.Fatalf("WriteJSONFile returned nil error for invalid value")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("invalid file stat error = %v, want not exist", statErr)
	}
}

func TestWriteJSONValidatesWritesIndentedJSONWithTrailingNewline(t *testing.T) {
	var out bytes.Buffer
	value := map[string]any{
		"schema_version": VersionResultSchemaID,
		"version":        "dev",
		"commit":         "unknown",
		"date":           "unknown",
		"go_version":     "go1.test",
		"os":             "testos",
		"arch":           "testarch",
	}

	if err := WriteJSON(&out, VersionResultSchemaID, value); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}
	if !strings.HasSuffix(out.String(), "\n") {
		t.Fatalf("written JSON missing trailing newline: %q", out.String())
	}
	if !strings.Contains(out.String(), "\n  \"schema_version\": \"covenant.version-result.v1\"") {
		t.Fatalf("written JSON is not indented: %q", out.String())
	}
	if err := ValidateBytes(VersionResultSchemaID, out.Bytes()); err != nil {
		t.Fatalf("written JSON did not validate: %v\njson:\n%s", err, out.String())
	}
}

func TestWriteJSONRejectsInvalidSchemaValueWithoutWriting(t *testing.T) {
	var out bytes.Buffer
	value := map[string]any{
		"schema_version": VersionResultSchemaID,
		"version":        "",
	}

	err := WriteJSON(&out, VersionResultSchemaID, value)
	if err == nil {
		t.Fatalf("WriteJSON returned nil error for invalid value")
	}
	if out.Len() != 0 {
		t.Fatalf("WriteJSON wrote %q for invalid value", out.String())
	}
}

func TestLintResultSchemaIsPublished(t *testing.T) {
	if !KnownSchemaID(LintResultSchemaID) {
		t.Fatalf("KnownSchemaID(%q) = false, want true", LintResultSchemaID)
	}
	found := false
	for _, entry := range Catalog() {
		if entry.ID == LintResultSchemaID {
			found = true
			if entry.FileName != "covenant.lint-result.v1.schema.json" {
				t.Fatalf("lint result schema file = %q", entry.FileName)
			}
			if entry.SchemaPath != schemaTestPath("covenant.lint-result.v1.schema.json") {
				t.Fatalf("lint result schema path = %q", entry.SchemaPath)
			}
		}
	}
	if !found {
		t.Fatalf("catalog missing %s", LintResultSchemaID)
	}
}

func TestSchemaValidationReportSchemaIsPublished(t *testing.T) {
	if !KnownSchemaID(SchemaValidationReportSchemaID) {
		t.Fatalf("KnownSchemaID(%q) = false, want true", SchemaValidationReportSchemaID)
	}
	found := false
	for _, entry := range Catalog() {
		if entry.ID == SchemaValidationReportSchemaID {
			found = true
			if entry.FileName != "covenant.schema-validation-report.v1.schema.json" {
				t.Fatalf("schema validation report file = %q", entry.FileName)
			}
			if entry.SchemaPath != schemaTestPath("covenant.schema-validation-report.v1.schema.json") {
				t.Fatalf("schema validation report path = %q", entry.SchemaPath)
			}
		}
	}
	if !found {
		t.Fatalf("catalog missing %s", SchemaValidationReportSchemaID)
	}
}

func TestCompileSummarySchemaIsPublished(t *testing.T) {
	if !KnownSchemaID(CompileSummarySchemaID) {
		t.Fatalf("KnownSchemaID(%q) = false, want true", CompileSummarySchemaID)
	}
	found := false
	for _, entry := range Catalog() {
		if entry.ID == CompileSummarySchemaID {
			found = true
			if entry.FileName != "covenant.compile-summary.v1.schema.json" {
				t.Fatalf("compile summary schema file = %q", entry.FileName)
			}
			if entry.SchemaPath != schemaTestPath("covenant.compile-summary.v1.schema.json") {
				t.Fatalf("compile summary schema path = %q", entry.SchemaPath)
			}
		}
	}
	if !found {
		t.Fatalf("catalog missing %s", CompileSummarySchemaID)
	}
}

func TestCompileResultSchemaIsPublished(t *testing.T) {
	if !KnownSchemaID(CompileResultSchemaID) {
		t.Fatalf("KnownSchemaID(%q) = false, want true", CompileResultSchemaID)
	}
	found := false
	for _, entry := range Catalog() {
		if entry.ID == CompileResultSchemaID {
			found = true
			if entry.FileName != "covenant.compile-result.v1.schema.json" {
				t.Fatalf("compile result schema file = %q", entry.FileName)
			}
			if entry.SchemaPath != schemaTestPath("covenant.compile-result.v1.schema.json") {
				t.Fatalf("compile result schema path = %q", entry.SchemaPath)
			}
		}
	}
	if !found {
		t.Fatalf("catalog missing %s", CompileResultSchemaID)
	}
}

func TestCompileResultSchemaDefinesStrictSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.compile-result.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "contract_path", "contract_digest", "contract_digest_file")
	if property(t, parsed, "schema_version")["const"] != CompileResultSchemaID {
		t.Fatalf("schema_version const = %v, want %s", property(t, parsed, "schema_version")["const"], CompileResultSchemaID)
	}
	for _, name := range []string{"contract_path", "contract_digest_file"} {
		if property(t, parsed, name)["minLength"] != float64(1) {
			t.Fatalf("%s minLength = %v, want 1", name, property(t, parsed, name)["minLength"])
		}
	}
	if property(t, parsed, "contract_digest")["pattern"] != "^[a-f0-9]{64}$" {
		t.Fatalf("contract_digest pattern = %v, want lowercase sha256", property(t, parsed, "contract_digest")["pattern"])
	}
}

func TestRunResultSchemaIsPublished(t *testing.T) {
	if !KnownSchemaID(RunResultSchemaID) {
		t.Fatalf("KnownSchemaID(%q) = false, want true", RunResultSchemaID)
	}
	found := false
	for _, entry := range Catalog() {
		if entry.ID == RunResultSchemaID {
			found = true
			if entry.FileName != "covenant.run-result.v1.schema.json" {
				t.Fatalf("run result schema file = %q", entry.FileName)
			}
			if entry.SchemaPath != schemaTestPath("covenant.run-result.v1.schema.json") {
				t.Fatalf("run result schema path = %q", entry.SchemaPath)
			}
		}
	}
	if !found {
		t.Fatalf("catalog missing %s", RunResultSchemaID)
	}
}

func TestSelfRunResultSchemaIsPublished(t *testing.T) {
	if !KnownSchemaID(SelfRunResultSchemaID) {
		t.Fatalf("KnownSchemaID(%q) = false, want true", SelfRunResultSchemaID)
	}
	found := false
	for _, entry := range Catalog() {
		if entry.ID == SelfRunResultSchemaID {
			found = true
			if entry.FileName != "covenant.self-run-result.v1.schema.json" {
				t.Fatalf("self-run result schema file = %q", entry.FileName)
			}
			if entry.SchemaPath != schemaTestPath("covenant.self-run-result.v1.schema.json") {
				t.Fatalf("self-run result schema path = %q", entry.SchemaPath)
			}
		}
	}
	if !found {
		t.Fatalf("catalog missing %s", SelfRunResultSchemaID)
	}
}

func TestVerifyResultSchemaIsPublished(t *testing.T) {
	if !KnownSchemaID(VerifyResultSchemaID) {
		t.Fatalf("KnownSchemaID(%q) = false, want true", VerifyResultSchemaID)
	}
	found := false
	for _, entry := range Catalog() {
		if entry.ID == VerifyResultSchemaID {
			found = true
			if entry.FileName != "covenant.verify-result.v1.schema.json" {
				t.Fatalf("verify result schema file = %q", entry.FileName)
			}
			if entry.SchemaPath != schemaTestPath("covenant.verify-result.v1.schema.json") {
				t.Fatalf("verify result schema path = %q", entry.SchemaPath)
			}
		}
	}
	if !found {
		t.Fatalf("catalog missing %s", VerifyResultSchemaID)
	}
}

func TestVersionResultSchemaIsPublished(t *testing.T) {
	if !KnownSchemaID(VersionResultSchemaID) {
		t.Fatalf("KnownSchemaID(%q) = false, want true", VersionResultSchemaID)
	}
	found := false
	for _, entry := range Catalog() {
		if entry.ID == VersionResultSchemaID {
			found = true
			if entry.FileName != "covenant.version-result.v1.schema.json" {
				t.Fatalf("version result schema file = %q", entry.FileName)
			}
			if entry.SchemaPath != schemaTestPath("covenant.version-result.v1.schema.json") {
				t.Fatalf("version result schema path = %q", entry.SchemaPath)
			}
		}
	}
	if !found {
		t.Fatalf("catalog missing %s", VersionResultSchemaID)
	}
}

func TestReleaseManifestSchemaIsPublished(t *testing.T) {
	if !KnownSchemaID(ReleaseManifestSchemaID) {
		t.Fatalf("KnownSchemaID(%q) = false, want true", ReleaseManifestSchemaID)
	}
	found := false
	for _, entry := range Catalog() {
		if entry.ID == ReleaseManifestSchemaID {
			found = true
			if entry.FileName != "covenant.release-manifest.v1.schema.json" {
				t.Fatalf("release manifest schema file = %q", entry.FileName)
			}
			if entry.SchemaPath != schemaTestPath("covenant.release-manifest.v1.schema.json") {
				t.Fatalf("release manifest schema path = %q", entry.SchemaPath)
			}
		}
	}
	if !found {
		t.Fatalf("catalog missing %s", ReleaseManifestSchemaID)
	}
}

func TestReleasePackageResultSchemaIsPublished(t *testing.T) {
	if !KnownSchemaID(ReleasePackageResultSchemaID) {
		t.Fatalf("KnownSchemaID(%q) = false, want true", ReleasePackageResultSchemaID)
	}
	found := false
	for _, entry := range Catalog() {
		if entry.ID == ReleasePackageResultSchemaID {
			found = true
			if entry.FileName != "covenant.release-package-result.v1.schema.json" {
				t.Fatalf("release package result schema file = %q", entry.FileName)
			}
			if entry.SchemaPath != schemaTestPath("covenant.release-package-result.v1.schema.json") {
				t.Fatalf("release package result schema path = %q", entry.SchemaPath)
			}
		}
	}
	if !found {
		t.Fatalf("catalog missing %s", ReleasePackageResultSchemaID)
	}
}

func TestReleaseVerifyResultSchemaIsPublished(t *testing.T) {
	if !KnownSchemaID(ReleaseVerifyResultSchemaID) {
		t.Fatalf("KnownSchemaID(%q) = false, want true", ReleaseVerifyResultSchemaID)
	}
	found := false
	for _, entry := range Catalog() {
		if entry.ID == ReleaseVerifyResultSchemaID {
			found = true
			if entry.FileName != "covenant.release-verify-result.v1.schema.json" {
				t.Fatalf("release verify result schema file = %q", entry.FileName)
			}
			if entry.SchemaPath != schemaTestPath("covenant.release-verify-result.v1.schema.json") {
				t.Fatalf("release verify result schema path = %q", entry.SchemaPath)
			}
		}
	}
	if !found {
		t.Fatalf("catalog missing %s", ReleaseVerifyResultSchemaID)
	}
}

func TestReleaseDiffResultSchemaIsPublished(t *testing.T) {
	if !KnownSchemaID(ReleaseDiffResultSchemaID) {
		t.Fatalf("KnownSchemaID(%q) = false, want true", ReleaseDiffResultSchemaID)
	}
	found := false
	for _, entry := range Catalog() {
		if entry.ID == ReleaseDiffResultSchemaID {
			found = true
			if entry.FileName != "covenant.release-diff-result.v1.schema.json" {
				t.Fatalf("release diff schema file = %q", entry.FileName)
			}
			if entry.SchemaPath != schemaTestPath("covenant.release-diff-result.v1.schema.json") {
				t.Fatalf("release diff schema path = %q", entry.SchemaPath)
			}
		}
	}
	if !found {
		t.Fatalf("catalog missing %s", ReleaseDiffResultSchemaID)
	}
}

func TestReleaseSignatureSchemaIsPublished(t *testing.T) {
	if !KnownSchemaID(ReleaseSignatureSchemaID) {
		t.Fatalf("KnownSchemaID(%q) = false, want true", ReleaseSignatureSchemaID)
	}
	found := false
	for _, entry := range Catalog() {
		if entry.ID == ReleaseSignatureSchemaID {
			found = true
			if entry.FileName != "covenant.release-signature.v1.schema.json" {
				t.Fatalf("release signature schema file = %q", entry.FileName)
			}
			if entry.SchemaPath != schemaTestPath("covenant.release-signature.v1.schema.json") {
				t.Fatalf("release signature schema path = %q", entry.SchemaPath)
			}
		}
	}
	if !found {
		t.Fatalf("catalog missing %s", ReleaseSignatureSchemaID)
	}
}

func TestReleaseInspectResultSchemaIsPublished(t *testing.T) {
	if !KnownSchemaID(ReleaseInspectResultSchemaID) {
		t.Fatalf("KnownSchemaID(%q) = false, want true", ReleaseInspectResultSchemaID)
	}
	found := false
	for _, entry := range Catalog() {
		if entry.ID == ReleaseInspectResultSchemaID {
			found = true
			if entry.FileName != "covenant.release-inspect-result.v1.schema.json" {
				t.Fatalf("release inspect result schema file = %q", entry.FileName)
			}
			if entry.SchemaPath != schemaTestPath("covenant.release-inspect-result.v1.schema.json") {
				t.Fatalf("release inspect result schema path = %q", entry.SchemaPath)
			}
		}
	}
	if !found {
		t.Fatalf("catalog missing %s", ReleaseInspectResultSchemaID)
	}
}

func TestReleaseReportResultSchemaIsPublished(t *testing.T) {
	if !KnownSchemaID(ReleaseReportResultSchemaID) {
		t.Fatalf("KnownSchemaID(%q) = false, want true", ReleaseReportResultSchemaID)
	}
	found := false
	for _, entry := range Catalog() {
		if entry.ID == ReleaseReportResultSchemaID {
			found = true
			if entry.FileName != "covenant.release-report-result.v1.schema.json" {
				t.Fatalf("release report result schema file = %q", entry.FileName)
			}
			if entry.SchemaPath != schemaTestPath("covenant.release-report-result.v1.schema.json") {
				t.Fatalf("release report result schema path = %q", entry.SchemaPath)
			}
		}
	}
	if !found {
		t.Fatalf("catalog missing %s", ReleaseReportResultSchemaID)
	}
}

func TestPolicyExplainResultSchemaIsPublished(t *testing.T) {
	if !KnownSchemaID(PolicyExplainResultSchemaID) {
		t.Fatalf("KnownSchemaID(%q) = false, want true", PolicyExplainResultSchemaID)
	}
	found := false
	for _, entry := range Catalog() {
		if entry.ID == PolicyExplainResultSchemaID {
			found = true
			if entry.FileName != "covenant.policy-explain-result.v1.schema.json" {
				t.Fatalf("policy explain result schema file = %q", entry.FileName)
			}
			if entry.SchemaPath != schemaTestPath("covenant.policy-explain-result.v1.schema.json") {
				t.Fatalf("policy explain result schema path = %q", entry.SchemaPath)
			}
		}
	}
	if !found {
		t.Fatalf("catalog missing %s", PolicyExplainResultSchemaID)
	}
}

func TestPolicyIndexResultSchemaIsPublished(t *testing.T) {
	if !KnownSchemaID(PolicyIndexResultSchemaID) {
		t.Fatalf("KnownSchemaID(%q) = false, want true", PolicyIndexResultSchemaID)
	}
	found := false
	for _, entry := range Catalog() {
		if entry.ID == PolicyIndexResultSchemaID {
			found = true
			if entry.FileName != "covenant.policy-index-result.v1.schema.json" {
				t.Fatalf("policy index result schema file = %q", entry.FileName)
			}
			if entry.SchemaPath != schemaTestPath("covenant.policy-index-result.v1.schema.json") {
				t.Fatalf("policy index result schema path = %q", entry.SchemaPath)
			}
		}
	}
	if !found {
		t.Fatalf("catalog missing %s", PolicyIndexResultSchemaID)
	}
}

func TestSchemaCatalogResultSchemaIsPublished(t *testing.T) {
	if !KnownSchemaID(SchemaCatalogResultSchemaID) {
		t.Fatalf("KnownSchemaID(%q) = false, want true", SchemaCatalogResultSchemaID)
	}
	found := false
	for _, entry := range Catalog() {
		if entry.ID == SchemaCatalogResultSchemaID {
			found = true
			if entry.FileName != "covenant.schema-catalog-result.v1.schema.json" {
				t.Fatalf("schema catalog result schema file = %q", entry.FileName)
			}
			if entry.SchemaPath != schemaTestPath("covenant.schema-catalog-result.v1.schema.json") {
				t.Fatalf("schema catalog result schema path = %q", entry.SchemaPath)
			}
		}
	}
	if !found {
		t.Fatalf("catalog missing %s", SchemaCatalogResultSchemaID)
	}
}

func TestSchemaExportResultSchemaIsPublished(t *testing.T) {
	if !KnownSchemaID(SchemaExportResultSchemaID) {
		t.Fatalf("KnownSchemaID(%q) = false, want true", SchemaExportResultSchemaID)
	}
	found := false
	for _, entry := range Catalog() {
		if entry.ID == SchemaExportResultSchemaID {
			found = true
			if entry.FileName != "covenant.schema-export-result.v1.schema.json" {
				t.Fatalf("schema export result schema file = %q", entry.FileName)
			}
			if entry.SchemaPath != schemaTestPath("covenant.schema-export-result.v1.schema.json") {
				t.Fatalf("schema export result schema path = %q", entry.SchemaPath)
			}
		}
	}
	if !found {
		t.Fatalf("catalog missing %s", SchemaExportResultSchemaID)
	}
}

func TestBundleInspectResultSchemaIsPublished(t *testing.T) {
	if !KnownSchemaID(BundleInspectResultSchemaID) {
		t.Fatalf("KnownSchemaID(%q) = false, want true", BundleInspectResultSchemaID)
	}
	found := false
	for _, entry := range Catalog() {
		if entry.ID == BundleInspectResultSchemaID {
			found = true
			if entry.FileName != "covenant.bundle-inspect-result.v1.schema.json" {
				t.Fatalf("bundle inspect result schema file = %q", entry.FileName)
			}
			if entry.SchemaPath != schemaTestPath("covenant.bundle-inspect-result.v1.schema.json") {
				t.Fatalf("bundle inspect result schema path = %q", entry.SchemaPath)
			}
		}
	}
	if !found {
		t.Fatalf("catalog missing %s", BundleInspectResultSchemaID)
	}
}

func TestBundleReportResultSchemaIsPublished(t *testing.T) {
	if !KnownSchemaID(BundleReportResultSchemaID) {
		t.Fatalf("KnownSchemaID(%q) = false, want true", BundleReportResultSchemaID)
	}
	found := false
	for _, entry := range Catalog() {
		if entry.ID == BundleReportResultSchemaID {
			found = true
			if entry.FileName != "covenant.bundle-report-result.v1.schema.json" {
				t.Fatalf("bundle report result schema file = %q", entry.FileName)
			}
			if entry.SchemaPath != schemaTestPath("covenant.bundle-report-result.v1.schema.json") {
				t.Fatalf("bundle report result schema path = %q", entry.SchemaPath)
			}
		}
	}
	if !found {
		t.Fatalf("catalog missing %s", BundleReportResultSchemaID)
	}
}

func TestBundleExportResultSchemaIsPublished(t *testing.T) {
	if !KnownSchemaID(BundleExportResultSchemaID) {
		t.Fatalf("KnownSchemaID(%q) = false, want true", BundleExportResultSchemaID)
	}
	found := false
	for _, entry := range Catalog() {
		if entry.ID == BundleExportResultSchemaID {
			found = true
			if entry.FileName != "covenant.bundle-export-result.v1.schema.json" {
				t.Fatalf("bundle export result schema file = %q", entry.FileName)
			}
			if entry.SchemaPath != schemaTestPath("covenant.bundle-export-result.v1.schema.json") {
				t.Fatalf("bundle export result schema path = %q", entry.SchemaPath)
			}
		}
	}
	if !found {
		t.Fatalf("catalog missing %s", BundleExportResultSchemaID)
	}
}

func TestBundleKeyFileSchemasArePublished(t *testing.T) {
	cases := []struct {
		id       string
		fileName string
	}{
		{BundlePrivateKeySchemaID, "covenant.bundle-private-key.v1.schema.json"},
		{BundlePublicKeySchemaID, "covenant.bundle-public-key.v1.schema.json"},
		{BundleSignatureSchemaID, "covenant.bundle-signature.v1.schema.json"},
	}
	for _, tc := range cases {
		if !KnownSchemaID(tc.id) {
			t.Fatalf("KnownSchemaID(%q) = false, want true", tc.id)
		}
		found := false
		for _, entry := range Catalog() {
			if entry.ID != tc.id {
				continue
			}
			found = true
			if entry.FileName != tc.fileName {
				t.Fatalf("%s file = %q", tc.id, entry.FileName)
			}
			if entry.SchemaPath != schemaTestPath(tc.fileName) {
				t.Fatalf("%s path = %q", tc.id, entry.SchemaPath)
			}
		}
		if !found {
			t.Fatalf("catalog missing %s", tc.id)
		}
	}
}

func TestBundleKeygenResultSchemaIsPublished(t *testing.T) {
	if !KnownSchemaID(BundleKeygenResultSchemaID) {
		t.Fatalf("KnownSchemaID(%q) = false, want true", BundleKeygenResultSchemaID)
	}
	found := false
	for _, entry := range Catalog() {
		if entry.ID == BundleKeygenResultSchemaID {
			found = true
			if entry.FileName != "covenant.bundle-keygen-result.v1.schema.json" {
				t.Fatalf("bundle keygen result schema file = %q", entry.FileName)
			}
			if entry.SchemaPath != schemaTestPath("covenant.bundle-keygen-result.v1.schema.json") {
				t.Fatalf("bundle keygen result schema path = %q", entry.SchemaPath)
			}
		}
	}
	if !found {
		t.Fatalf("catalog missing %s", BundleKeygenResultSchemaID)
	}
}

func TestExportWritesEmbeddedSchemas(t *testing.T) {
	dir := t.TempDir()

	written, err := Export(dir)
	if err != nil {
		t.Fatalf("Export returned error: %v", err)
	}

	required := RequiredFiles()
	if len(written) != len(required) {
		t.Fatalf("written len = %d, want %d", len(written), len(required))
	}
	for index, entry := range written {
		requiredEntry := required[index]
		wantPath := filepath.Join(dir, requiredEntry.FileName)
		if entry.ID != requiredEntry.ID || entry.FileName != requiredEntry.FileName || entry.SchemaPath != schemaTestPath(requiredEntry.FileName) {
			t.Fatalf("written[%d] = %+v, want catalog entry for %+v", index, entry, requiredEntry)
		}
		if entry.WrittenPath != wantPath {
			t.Fatalf("written[%d].WrittenPath = %q, want %q", index, entry.WrittenPath, wantPath)
		}
		bytes, err := os.ReadFile(wantPath)
		if err != nil {
			t.Fatalf("read exported schema %s: %v", wantPath, err)
		}
		var parsed map[string]any
		if err := json.Unmarshal(bytes, &parsed); err != nil {
			t.Fatalf("parse exported schema %s: %v", wantPath, err)
		}
		if parsed["$id"] != requiredEntry.ID {
			t.Fatalf("exported %s $id = %v, want %s", wantPath, parsed["$id"], requiredEntry.ID)
		}
	}
}

func TestValidateDocumentBytesReportsValidDocument(t *testing.T) {
	bytes, err := json.Marshal(validContractDocument())
	if err != nil {
		t.Fatalf("marshal valid contract: %v", err)
	}

	report := ValidateDocumentBytes(ContractSchemaID, bytes)

	if !report.Valid {
		t.Fatalf("report.Valid = false, want true; error = %q", report.Error)
	}
	if report.SchemaID != ContractSchemaID {
		t.Fatalf("SchemaID = %q, want %q", report.SchemaID, ContractSchemaID)
	}
	if report.Error != "" {
		t.Fatalf("Error = %q, want empty", report.Error)
	}
}

func TestValidateDocumentBytesReportsInvalidDocument(t *testing.T) {
	report := ValidateDocumentBytes(ContractSchemaID, []byte(`{"schema_version":"covenant.contract.v1"}`))

	if report.Valid {
		t.Fatalf("report.Valid = true, want false")
	}
	if report.SchemaID != ContractSchemaID {
		t.Fatalf("SchemaID = %q, want %q", report.SchemaID, ContractSchemaID)
	}
	if !strings.Contains(report.Error, "schema validation failed for covenant.contract.v1") {
		t.Fatalf("Error = %q, want schema validation failure", report.Error)
	}
}

func TestValidateDocumentBytesReportsRootLocation(t *testing.T) {
	report := ValidateDocumentBytes(ContractSchemaID, []byte(`{"schema_version":"covenant.contract.v1"}`))

	if report.Valid {
		t.Fatalf("report.Valid = true, want false")
	}
	if report.Location != "/" {
		t.Fatalf("Location = %q, want root pointer", report.Location)
	}
}

func TestValidateDocumentBytesReportsNestedLocation(t *testing.T) {
	document := validContractDocument()
	tasks := document["tasks"].([]any)
	task := tasks[0].(map[string]any)
	task["timeout_seconds"] = "slow"
	bytes, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal invalid contract: %v", err)
	}

	report := ValidateDocumentBytes(ContractSchemaID, bytes)

	if report.Valid {
		t.Fatalf("report.Valid = true, want false")
	}
	if report.Location != "/tasks/0/timeout_seconds" {
		t.Fatalf("Location = %q, want nested JSON pointer", report.Location)
	}
	if !strings.Contains(report.Error, report.Location) {
		t.Fatalf("Error = %q, want location %q", report.Error, report.Location)
	}
}

func TestValidationSARIFRendersInvalidReports(t *testing.T) {
	log := ValidationSARIF([]ValidationSARIFReport{
		{
			SchemaID: ContractSchemaID,
			File:     "contract.json",
			Valid:    false,
			Error:    "schema validation failed for covenant.contract.v1: missing properties: tasks",
			Location: "/tasks/0/timeout_seconds",
		},
	})

	if log.Schema != "https://json.schemastore.org/sarif-2.1.0.json" || log.Version != "2.1.0" {
		t.Fatalf("sarif metadata = %q %q, want SARIF 2.1.0", log.Schema, log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs len = %d, want 1", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "AO Covenant Schema Validator" || run.Tool.Driver.InformationURI == "" {
		t.Fatalf("driver = %+v, want schema validator driver with information URI", run.Tool.Driver)
	}
	if len(run.Tool.Driver.Rules) != 1 || run.Tool.Driver.Rules[0].ID != "SCHEMA_VALIDATION_FAILED" {
		t.Fatalf("rules = %+v, want validation failure rule", run.Tool.Driver.Rules)
	}
	if len(run.Results) != 1 {
		t.Fatalf("results len = %d, want 1", len(run.Results))
	}
	result := run.Results[0]
	if result.RuleID != "SCHEMA_VALIDATION_FAILED" || result.Level != "error" {
		t.Fatalf("result rule/level = %s/%s, want schema error", result.RuleID, result.Level)
	}
	if !strings.Contains(result.Message.Text, "missing properties: tasks") {
		t.Fatalf("message = %q, want validation error text", result.Message.Text)
	}
	if len(result.Locations) != 1 || result.Locations[0].PhysicalLocation.ArtifactLocation.URI != "contract.json" {
		t.Fatalf("locations = %+v, want contract.json artifact location", result.Locations)
	}
	if result.Properties.SchemaID != ContractSchemaID {
		t.Fatalf("schema property = %q, want %q", result.Properties.SchemaID, ContractSchemaID)
	}
	if result.Properties.Location != "/tasks/0/timeout_seconds" {
		t.Fatalf("location property = %q, want nested pointer", result.Properties.Location)
	}
}

func TestValidationSARIFAppliesBaselineSuppression(t *testing.T) {
	log := ValidationSARIFWithOptions([]ValidationSARIFReport{
		{
			SchemaID: ContractSchemaID,
			File:     "contract.json",
			Valid:    false,
			Error:    "schema validation failed for covenant.contract.v1: missing properties: tasks",
			Location: "/tasks",
		},
	}, ValidationSARIFOptions{
		Baseline: SARIFBaseline{
			Accepted: []SARIFBaselineEntry{
				{
					RuleID:        "SCHEMA_VALIDATION_FAILED",
					SourceURI:     "contract.json",
					Field:         "/tasks",
					Justification: "accepted generated fixture drift",
				},
			},
		},
	})

	result := log.Runs[0].Results[0]
	if len(result.Suppressions) != 1 {
		t.Fatalf("suppressions = %+v, want one", result.Suppressions)
	}
	if result.Suppressions[0].Kind != "external" || result.Suppressions[0].Justification != "accepted generated fixture drift" {
		t.Fatalf("suppression = %+v, want external justification", result.Suppressions[0])
	}
	if !ValidationSARIFReportsAllSuppressed([]ValidationSARIFReport{
		{SchemaID: ContractSchemaID, File: "contract.json", Valid: false, Error: "schema validation failed", Location: "/tasks"},
	}, ValidationSARIFOptions{
		Baseline: SARIFBaseline{
			Accepted: []SARIFBaselineEntry{
				{RuleID: "SCHEMA_VALIDATION_FAILED", SourceURI: "contract.json", Field: "/tasks", Justification: "accepted generated fixture drift"},
			},
		},
	}) {
		t.Fatalf("all suppressed = false, want true")
	}
}

func TestValidationSARIFBaselineDoesNotSuppressDifferentLocation(t *testing.T) {
	reports := []ValidationSARIFReport{
		{
			SchemaID: ContractSchemaID,
			File:     "contract.json",
			Valid:    false,
			Error:    "schema validation failed for covenant.contract.v1: missing properties: tasks",
			Location: "/tasks",
		},
	}
	opts := ValidationSARIFOptions{
		Baseline: SARIFBaseline{
			Accepted: []SARIFBaselineEntry{
				{RuleID: "SCHEMA_VALIDATION_FAILED", SourceURI: "contract.json", Field: "/workspace", Justification: "accepted different failure"},
			},
		},
	}

	log := ValidationSARIFWithOptions(reports, opts)

	if len(log.Runs[0].Results[0].Suppressions) != 0 {
		t.Fatalf("suppressions = %+v, want none", log.Runs[0].Results[0].Suppressions)
	}
	if ValidationSARIFReportsAllSuppressed(reports, opts) {
		t.Fatalf("all suppressed = true, want false")
	}
}

func TestValidationSARIFOmitsValidReports(t *testing.T) {
	log := ValidationSARIF([]ValidationSARIFReport{
		{SchemaID: ContractSchemaID, File: "contract.json", Valid: true},
	})

	if len(log.Runs) != 1 {
		t.Fatalf("runs len = %d, want 1", len(log.Runs))
	}
	if len(log.Runs[0].Results) != 0 {
		t.Fatalf("results = %+v, want no SARIF findings for valid documents", log.Runs[0].Results)
	}
	if len(log.Runs[0].Tool.Driver.Rules) != 0 {
		t.Fatalf("rules = %+v, want no rules when there are no findings", log.Runs[0].Tool.Driver.Rules)
	}
}

func TestValidationJUnitRendersInvalidReports(t *testing.T) {
	report := ValidationJUnit([]ValidationJUnitReport{
		{
			SchemaID: ContractSchemaID,
			File:     "contract.json",
			Valid:    false,
			Error:    "schema validation failed for covenant.contract.v1: missing properties: tasks",
			Location: "/tasks/0/timeout_seconds",
		},
	}, "AO Covenant schema validation")

	if report.Tests != 1 || report.Failures != 1 {
		t.Fatalf("junit aggregate = tests %d failures %d, want 1/1", report.Tests, report.Failures)
	}
	if len(report.TestSuites) != 1 {
		t.Fatalf("test suites len = %d, want 1", len(report.TestSuites))
	}
	suite := report.TestSuites[0]
	if suite.Name != "AO Covenant schema validation" || suite.Tests != 1 || suite.Failures != 1 {
		t.Fatalf("suite = %+v, want named failing suite", suite)
	}
	if len(suite.TestCases) != 1 {
		t.Fatalf("test cases len = %d, want 1", len(suite.TestCases))
	}
	testCase := suite.TestCases[0]
	if testCase.ClassName != ContractSchemaID || testCase.Name != "contract.json" {
		t.Fatalf("test case = %+v, want schema classname and file name", testCase)
	}
	if testCase.Failure == nil {
		t.Fatalf("test case failure = nil, want validation failure")
	}
	if testCase.Failure.Message != "schema validation failed" {
		t.Fatalf("failure message = %q, want stable failure summary", testCase.Failure.Message)
	}
	if !strings.Contains(testCase.Failure.Text, "missing properties: tasks") {
		t.Fatalf("failure text = %q, want validation error detail", testCase.Failure.Text)
	}
	if !strings.Contains(testCase.Failure.Text, "location=/tasks/0/timeout_seconds") {
		t.Fatalf("failure text = %q, want location", testCase.Failure.Text)
	}
}

func TestValidationJUnitRendersValidReports(t *testing.T) {
	report := ValidationJUnit([]ValidationJUnitReport{
		{SchemaID: ContractSchemaID, File: "contract.json", Valid: true},
	}, "")

	if report.Tests != 1 || report.Failures != 0 {
		t.Fatalf("junit aggregate = tests %d failures %d, want 1/0", report.Tests, report.Failures)
	}
	if len(report.TestSuites) != 1 {
		t.Fatalf("test suites len = %d, want 1", len(report.TestSuites))
	}
	suite := report.TestSuites[0]
	if suite.Name != "AO Covenant schema validation" || suite.Tests != 1 || suite.Failures != 0 {
		t.Fatalf("suite = %+v, want default passing suite", suite)
	}
	if len(suite.TestCases) != 1 {
		t.Fatalf("test cases len = %d, want 1", len(suite.TestCases))
	}
	if suite.TestCases[0].Failure != nil {
		t.Fatalf("failure = %+v, want nil for valid report", suite.TestCases[0].Failure)
	}
}

func TestInferSchemaIDBytesReturnsKnownSchemaVersion(t *testing.T) {
	bytes, err := json.Marshal(validContractDocument())
	if err != nil {
		t.Fatalf("marshal valid contract: %v", err)
	}

	schemaID, err := InferSchemaIDBytes(bytes)

	if err != nil {
		t.Fatalf("InferSchemaIDBytes returned error: %v", err)
	}
	if schemaID != ContractSchemaID {
		t.Fatalf("schemaID = %q, want %q", schemaID, ContractSchemaID)
	}
}

func TestInferSchemaIDBytesRejectsMissingSchemaVersion(t *testing.T) {
	_, err := InferSchemaIDBytes([]byte(`{"id":"contract_demo"}`))

	if err == nil {
		t.Fatalf("InferSchemaIDBytes returned nil error, want missing schema_version error")
	}
	if !strings.Contains(err.Error(), "schema_version is required") {
		t.Fatalf("error = %v, want schema_version requirement", err)
	}
}

func TestInferSchemaIDBytesRejectsUnknownSchemaVersion(t *testing.T) {
	_, err := InferSchemaIDBytes([]byte(`{"schema_version":"covenant.unknown.v1"}`))

	if err == nil {
		t.Fatalf("InferSchemaIDBytes returned nil error, want unknown schema error")
	}
	if !strings.Contains(err.Error(), `unknown schema "covenant.unknown.v1"`) {
		t.Fatalf("error = %v, want unknown schema context", err)
	}
}

func TestContractSchemaDefinesNestedContractSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.contract.v1.schema.json")

	workspace := property(t, parsed, "workspace")
	requireBool(t, workspace, "additionalProperties", false)
	requireRequired(t, workspace, "root", "reads", "writes")

	obligations := property(t, parsed, "obligations")
	items := asMap(t, obligations["items"], "obligation items")
	requireBool(t, items, "additionalProperties", false)
	requireRequired(t, items, "id", "text", "required")

	policy := property(t, parsed, "policy")
	requireBool(t, policy, "additionalProperties", false)
	requireRequired(t, policy, "mode")

	evaluator := property(t, parsed, "evaluator")
	requireBool(t, evaluator, "additionalProperties", false)
	requireRequired(t, evaluator, "required_obligations")

	approvals := property(t, parsed, "approvals")
	approvalItems := asMap(t, approvals["items"], "approval items")
	requireRef(t, approvalItems, "covenant.approval-ticket.v1")

	defs := asMap(t, parsed["$defs"], "$defs")
	if _, ok := defs["portable_id"]; !ok {
		t.Fatalf("contract schema missing portable_id definition")
	}
	if _, ok := defs["workspace_path"]; !ok {
		t.Fatalf("contract schema missing workspace_path definition")
	}
}

func TestTaskSchemaDefinesPortableTaskSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.task.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "id", "kind", "adapter", "depends_on", "obligations", "timeout_seconds")

	kind := property(t, parsed, "kind")
	requireEnum(t, kind, "scripted", "shell", "agent", "verify", "review", "evaluate")

	sideEffects := property(t, parsed, "declared_side_effects")
	items := asMap(t, sideEffects["items"], "declared_side_effects items")
	requireBool(t, items, "additionalProperties", false)
	requireRequired(t, items, "type", "resource")
}

func TestApprovalTicketSchemaDefinesStrictApprovalSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.approval-ticket.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "ticket_id", "task_id", "effect_type", "resource", "approved", "reason")
	requirePattern(t, property(t, parsed, "ticket_id"))
	requirePattern(t, property(t, parsed, "task_id"))
	requirePattern(t, property(t, parsed, "resource"))
	requirePattern(t, property(t, parsed, "operator_id"))
	if property(t, parsed, "expires_at")["format"] != "date-time" {
		t.Fatalf("expires_at format = %v, want date-time", property(t, parsed, "expires_at")["format"])
	}
	effectType := property(t, parsed, "effect_type")
	requireEnum(t, effectType, "file.write", "file.read", "process.spawn", "network.request")
}

func TestApprovalRevocationsSchemaDefinesStrictRevocationSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.approval-revocations.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "revoked_tickets")

	revokedTickets := property(t, parsed, "revoked_tickets")
	items := asMap(t, revokedTickets["items"], "revoked_tickets items")
	requireBool(t, items, "additionalProperties", false)
	requireRequired(t, items, "ticket_id", "reason")
	requirePattern(t, property(t, items, "ticket_id"))
	if property(t, items, "reason")["minLength"] != float64(1) {
		t.Fatalf("reason minLength = %v, want 1", property(t, items, "reason")["minLength"])
	}
}

func TestApprovalCommandResultSchemasArePublished(t *testing.T) {
	tests := []struct {
		id       string
		fileName string
	}{
		{ApprovalCreateResultSchemaID, "covenant.approval-create-result.v1.schema.json"},
		{ApprovalValidateResultSchemaID, "covenant.approval-validate-result.v1.schema.json"},
		{ApprovalAttachResultSchemaID, "covenant.approval-attach-result.v1.schema.json"},
	}

	for _, tt := range tests {
		if !KnownSchemaID(tt.id) {
			t.Fatalf("KnownSchemaID(%q) = false, want true", tt.id)
		}
		found := false
		for _, entry := range Catalog() {
			if entry.ID == tt.id {
				found = true
				if entry.FileName != tt.fileName {
					t.Fatalf("%s file = %q, want %q", tt.id, entry.FileName, tt.fileName)
				}
				if entry.SchemaPath != schemaTestPath(tt.fileName) {
					t.Fatalf("%s schema path = %q", tt.id, entry.SchemaPath)
				}
			}
		}
		if !found {
			t.Fatalf("catalog missing %s", tt.id)
		}
	}
}

func TestApprovalRevocationResultSchemasArePublished(t *testing.T) {
	tests := []struct {
		id       string
		fileName string
	}{
		{ApprovalRevokeResultSchemaID, "covenant.approval-revoke-result.v1.schema.json"},
		{ApprovalRevocationsInspectResultSchemaID, "covenant.approval-revocations-inspect-result.v1.schema.json"},
	}

	for _, tt := range tests {
		if !KnownSchemaID(tt.id) {
			t.Fatalf("KnownSchemaID(%q) = false, want true", tt.id)
		}
		found := false
		for _, entry := range Catalog() {
			if entry.ID == tt.id {
				found = true
				if entry.FileName != tt.fileName {
					t.Fatalf("%s file = %q, want %q", tt.id, entry.FileName, tt.fileName)
				}
				if entry.SchemaPath != schemaTestPath(tt.fileName) {
					t.Fatalf("%s schema path = %q", tt.id, entry.SchemaPath)
				}
			}
		}
		if !found {
			t.Fatalf("catalog missing %s", tt.id)
		}
	}
}

func TestApprovalCommandResultSchemasDefineStrictSurfaces(t *testing.T) {
	create := readSchema(t, "covenant.approval-create-result.v1.schema.json")
	requireBool(t, create, "additionalProperties", false)
	requireRequired(t, create, "schema_version", "ticket_path", "ticket")
	if property(t, create, "schema_version")["const"] != ApprovalCreateResultSchemaID {
		t.Fatalf("create schema_version const = %v, want %s", property(t, create, "schema_version")["const"], ApprovalCreateResultSchemaID)
	}
	if property(t, create, "ticket_path")["minLength"] != float64(1) {
		t.Fatalf("ticket_path minLength = %v, want 1", property(t, create, "ticket_path")["minLength"])
	}
	requireRef(t, property(t, create, "ticket"), ApprovalTicketSchemaID)

	validate := readSchema(t, "covenant.approval-validate-result.v1.schema.json")
	requireBool(t, validate, "additionalProperties", false)
	requireRequired(t, validate, "schema_version", "valid", "ticket_id")
	if property(t, validate, "schema_version")["const"] != ApprovalValidateResultSchemaID {
		t.Fatalf("validate schema_version const = %v, want %s", property(t, validate, "schema_version")["const"], ApprovalValidateResultSchemaID)
	}
	if property(t, validate, "valid")["const"] != true {
		t.Fatalf("valid const = %v, want true", property(t, validate, "valid")["const"])
	}
	if property(t, validate, "ticket_id")["minLength"] != float64(1) {
		t.Fatalf("ticket_id minLength = %v, want 1", property(t, validate, "ticket_id")["minLength"])
	}
	if property(t, validate, "contract_path")["minLength"] != float64(1) {
		t.Fatalf("contract_path minLength = %v, want 1", property(t, validate, "contract_path")["minLength"])
	}

	attach := readSchema(t, "covenant.approval-attach-result.v1.schema.json")
	requireBool(t, attach, "additionalProperties", false)
	requireRequired(t, attach, "schema_version", "contract_path", "contract_digest", "approval_count", "ticket_id")
	if property(t, attach, "schema_version")["const"] != ApprovalAttachResultSchemaID {
		t.Fatalf("attach schema_version const = %v, want %s", property(t, attach, "schema_version")["const"], ApprovalAttachResultSchemaID)
	}
	if property(t, attach, "contract_path")["minLength"] != float64(1) {
		t.Fatalf("contract_path minLength = %v, want 1", property(t, attach, "contract_path")["minLength"])
	}
	if property(t, attach, "contract_digest")["pattern"] != "^[a-f0-9]{64}$" {
		t.Fatalf("contract_digest pattern = %v, want lowercase sha256", property(t, attach, "contract_digest")["pattern"])
	}
	if property(t, attach, "approval_count")["minimum"] != float64(1) {
		t.Fatalf("approval_count minimum = %v, want 1", property(t, attach, "approval_count")["minimum"])
	}
	if property(t, attach, "ticket_id")["minLength"] != float64(1) {
		t.Fatalf("ticket_id minLength = %v, want 1", property(t, attach, "ticket_id")["minLength"])
	}
}

func TestApprovalRevocationResultSchemasDefineStrictSurfaces(t *testing.T) {
	revoke := readSchema(t, "covenant.approval-revoke-result.v1.schema.json")
	requireBool(t, revoke, "additionalProperties", false)
	requireRequired(t, revoke, "schema_version", "revocations_path", "revoked_ticket_count", "ticket_id", "revocations")
	if property(t, revoke, "schema_version")["const"] != ApprovalRevokeResultSchemaID {
		t.Fatalf("revoke schema_version const = %v, want %s", property(t, revoke, "schema_version")["const"], ApprovalRevokeResultSchemaID)
	}
	if property(t, revoke, "revocations_path")["minLength"] != float64(1) {
		t.Fatalf("revoke revocations_path minLength = %v, want 1", property(t, revoke, "revocations_path")["minLength"])
	}
	if property(t, revoke, "revoked_ticket_count")["minimum"] != float64(1) {
		t.Fatalf("revoke revoked_ticket_count minimum = %v, want 1", property(t, revoke, "revoked_ticket_count")["minimum"])
	}
	if property(t, revoke, "ticket_id")["minLength"] != float64(1) {
		t.Fatalf("revoke ticket_id minLength = %v, want 1", property(t, revoke, "ticket_id")["minLength"])
	}
	requireRef(t, property(t, revoke, "revocations"), ApprovalRevocationsSchemaID)

	inspect := readSchema(t, "covenant.approval-revocations-inspect-result.v1.schema.json")
	requireBool(t, inspect, "additionalProperties", false)
	requireRequired(t, inspect, "schema_version", "revocations_path", "revoked_ticket_count", "revocations")
	if property(t, inspect, "schema_version")["const"] != ApprovalRevocationsInspectResultSchemaID {
		t.Fatalf("inspect schema_version const = %v, want %s", property(t, inspect, "schema_version")["const"], ApprovalRevocationsInspectResultSchemaID)
	}
	if property(t, inspect, "revocations_path")["minLength"] != float64(1) {
		t.Fatalf("inspect revocations_path minLength = %v, want 1", property(t, inspect, "revocations_path")["minLength"])
	}
	if property(t, inspect, "revoked_ticket_count")["minimum"] != float64(0) {
		t.Fatalf("inspect revoked_ticket_count minimum = %v, want 0", property(t, inspect, "revoked_ticket_count")["minimum"])
	}
	requireRef(t, property(t, inspect, "revocations"), ApprovalRevocationsSchemaID)
}

func TestEventSchemaDefinesRunLedgerSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.event.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "event_id", "sequence", "run_id", "previous_event_hash", "event_hash", "type", "status")

	requirePattern(t, property(t, parsed, "run_id"))
	requirePattern(t, property(t, parsed, "previous_event_hash"))
	requirePattern(t, property(t, parsed, "event_hash"))
	eventType := property(t, parsed, "type")
	requireEnum(t, eventType, "run_started", "task_started", "policy_decided", "artifact_recorded", "task_finished", "run_finished")

	status := property(t, parsed, "status")
	requireEnum(t, status, "success", "failed")
}

func TestEventSchemaDefinesStrictPolicyEventRules(t *testing.T) {
	parsed := readSchema(t, "covenant.event.v1.schema.json")
	allOf, ok := parsed["allOf"].([]any)
	if !ok || len(allOf) < 2 {
		t.Fatalf("event schema allOf = %T len %d, want conditional policy rules", parsed["allOf"], len(allOf))
	}
	policyRule := asMap(t, allOf[0], "policy event rule")
	then := asMap(t, policyRule["then"], "policy event then")
	requireRequired(t, then, "task_id", "decision_id", "decision", "effect_type", "resource")
}

func TestEvidencePackSchemaDefinesArtifactManifestSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.evidence-pack.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "run_id", "contract_digest", "ledger_digest", "run_status", "artifact_manifest", "input_snapshots", "policy_decisions", "failures", "closure_matrix")

	requirePattern(t, property(t, parsed, "run_id"))
	requirePattern(t, property(t, parsed, "ledger_digest"))
	runStatus := property(t, parsed, "run_status")
	requireEnum(t, runStatus, "success", "failed")

	manifest := property(t, parsed, "artifact_manifest")
	items := asMap(t, manifest["items"], "artifact_manifest items")
	requireRef(t, items, "covenant.artifact-ref.v1")

	inputSnapshots := property(t, parsed, "input_snapshots")
	snapshotItems := asMap(t, inputSnapshots["items"], "input_snapshots items")
	requireRef(t, snapshotItems, "covenant.input-snapshot.v1")

	policyDecisions := property(t, parsed, "policy_decisions")
	decisionItems := asMap(t, policyDecisions["items"], "policy_decisions items")
	requireRef(t, decisionItems, "covenant.policy-decision.v1")

	failures := property(t, parsed, "failures")
	failureItems := asMap(t, failures["items"], "failures items")
	requireRef(t, failureItems, "covenant.failure.v1")

	closureMatrix := property(t, parsed, "closure_matrix")
	requireRef(t, closureMatrix, "covenant.closure-matrix.v1")
}

func TestEvidenceBundleSchemaDefinesStrictManifestSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.evidence-bundle.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "run_id", "contract_digest", "ledger_digest", "verification", "entries")

	requirePattern(t, property(t, parsed, "run_id"))
	requirePattern(t, property(t, parsed, "contract_digest"))
	requirePattern(t, property(t, parsed, "ledger_digest"))

	verification := property(t, parsed, "verification")
	requireBool(t, verification, "additionalProperties", false)
	requireRequired(t, verification, "verified", "event_count", "artifact_count", "input_snapshot_count", "failure_count")

	entries := property(t, parsed, "entries")
	entry := asMap(t, entries["items"], "bundle manifest entry")
	requireBool(t, entry, "additionalProperties", false)
	requireRequired(t, entry, "path", "source", "sha256", "size_bytes")
	requirePattern(t, property(t, entry, "path"))
	requirePattern(t, property(t, entry, "sha256"))
	if property(t, entry, "size_bytes")["minimum"] != float64(0) {
		t.Fatalf("size_bytes minimum = %v, want 0", property(t, entry, "size_bytes")["minimum"])
	}
}

func TestBundleKeygenResultSchemaDefinesStrictSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.bundle-keygen-result.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "private_key_path", "public_key_path", "public_key_sha256")
	if property(t, parsed, "schema_version")["const"] != BundleKeygenResultSchemaID {
		t.Fatalf("schema_version const = %v, want %s", property(t, parsed, "schema_version")["const"], BundleKeygenResultSchemaID)
	}
	if property(t, parsed, "private_key_path")["minLength"] != float64(1) {
		t.Fatalf("private_key_path minLength = %v, want 1", property(t, parsed, "private_key_path")["minLength"])
	}
	if property(t, parsed, "public_key_path")["minLength"] != float64(1) {
		t.Fatalf("public_key_path minLength = %v, want 1", property(t, parsed, "public_key_path")["minLength"])
	}
	if property(t, parsed, "public_key_sha256")["pattern"] != "^[a-f0-9]{64}$" {
		t.Fatalf("public_key_sha256 pattern = %v, want lowercase sha256", property(t, parsed, "public_key_sha256")["pattern"])
	}
}

func TestBundleExportResultSchemaDefinesStrictSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.bundle-export-result.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "bundle_path", "entry_count", "manifest")
	if property(t, parsed, "schema_version")["const"] != BundleExportResultSchemaID {
		t.Fatalf("schema_version const = %v, want %s", property(t, parsed, "schema_version")["const"], BundleExportResultSchemaID)
	}
	if property(t, parsed, "bundle_path")["minLength"] != float64(1) {
		t.Fatalf("bundle_path minLength = %v, want 1", property(t, parsed, "bundle_path")["minLength"])
	}
	if property(t, parsed, "entry_count")["minimum"] != float64(1) {
		t.Fatalf("entry_count minimum = %v, want 1", property(t, parsed, "entry_count")["minimum"])
	}
	if property(t, parsed, "public_key_sha256")["pattern"] != "^[a-f0-9]{64}$" {
		t.Fatalf("public_key_sha256 pattern = %v, want lowercase sha256", property(t, parsed, "public_key_sha256")["pattern"])
	}
	manifest := property(t, parsed, "manifest")
	if manifest["$ref"] != "covenant.evidence-bundle.v1" {
		t.Fatalf("manifest ref = %v, want covenant.evidence-bundle.v1", manifest["$ref"])
	}
}

func TestRunResultSchemaDefinesStrictSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.run-result.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "run_id", "run_dir", "ledger_path", "evidence_pack_path")
	if property(t, parsed, "schema_version")["const"] != RunResultSchemaID {
		t.Fatalf("schema_version const = %v, want %s", property(t, parsed, "schema_version")["const"], RunResultSchemaID)
	}
	for _, name := range []string{"run_id", "run_dir", "ledger_path", "evidence_pack_path"} {
		if property(t, parsed, name)["minLength"] != float64(1) {
			t.Fatalf("%s minLength = %v, want 1", name, property(t, parsed, name)["minLength"])
		}
	}
}

func TestSelfRunResultSchemaDefinesStrictSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.self-run-result.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "contract_path", "contract_digest", "contract_digest_file", "run_id", "run_dir", "ledger_path", "evidence_pack_path", "verified", "failure_count")
	if property(t, parsed, "schema_version")["const"] != SelfRunResultSchemaID {
		t.Fatalf("schema_version const = %v, want %s", property(t, parsed, "schema_version")["const"], SelfRunResultSchemaID)
	}
	for _, name := range []string{"contract_path", "contract_digest_file", "run_id", "run_dir", "ledger_path", "evidence_pack_path"} {
		if property(t, parsed, name)["minLength"] != float64(1) {
			t.Fatalf("%s minLength = %v, want 1", name, property(t, parsed, name)["minLength"])
		}
	}
	if property(t, parsed, "contract_digest")["pattern"] != "^[a-f0-9]{64}$" {
		t.Fatalf("contract_digest pattern = %v, want lowercase sha256", property(t, parsed, "contract_digest")["pattern"])
	}
	if property(t, parsed, "failure_count")["minimum"] != float64(0) {
		t.Fatalf("failure_count minimum = %v, want 0", property(t, parsed, "failure_count")["minimum"])
	}
}

func TestReleaseManifestSchemaDefinesStrictManifestSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.release-manifest.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "version", "commit", "date", "artifacts")

	if property(t, parsed, "schema_version")["const"] != ReleaseManifestSchemaID {
		t.Fatalf("schema_version const = %v, want %s", property(t, parsed, "schema_version")["const"], ReleaseManifestSchemaID)
	}
	for _, name := range []string{"version", "commit", "date"} {
		if property(t, parsed, name)["minLength"] != float64(1) {
			t.Fatalf("%s minLength = %v, want 1", name, property(t, parsed, name)["minLength"])
		}
	}

	artifacts := property(t, parsed, "artifacts")
	if artifacts["minItems"] != float64(1) {
		t.Fatalf("artifacts minItems = %v, want 1", artifacts["minItems"])
	}
	artifact := asMap(t, artifacts["items"], "release manifest artifact")
	requireBool(t, artifact, "additionalProperties", false)
	requireRequired(t, artifact, "name", "target", "path", "sha256", "size_bytes")
	for _, name := range []string{"name", "path"} {
		if property(t, artifact, name)["minLength"] != float64(1) {
			t.Fatalf("artifact %s minLength = %v, want 1", name, property(t, artifact, name)["minLength"])
		}
	}
	requirePattern(t, property(t, artifact, "sha256"))
	if property(t, artifact, "size_bytes")["minimum"] != float64(1) {
		t.Fatalf("size_bytes minimum = %v, want 1", property(t, artifact, "size_bytes")["minimum"])
	}
	attestations := property(t, artifact, "attestations")
	attestation := asMap(t, attestations["items"], "release artifact attestation")
	requireBool(t, attestation, "additionalProperties", false)
	requireRequired(t, attestation, "name", "path", "sha256", "size_bytes")
	for _, name := range []string{"name", "kind", "path"} {
		if property(t, attestation, name)["minLength"] != float64(1) {
			t.Fatalf("attestation %s minLength = %v, want 1", name, property(t, attestation, name)["minLength"])
		}
	}
	requirePattern(t, property(t, attestation, "sha256"))
	if property(t, attestation, "size_bytes")["minimum"] != float64(1) {
		t.Fatalf("attestation size_bytes minimum = %v, want 1", property(t, attestation, "size_bytes")["minimum"])
	}

	target := property(t, artifact, "target")
	requireBool(t, target, "additionalProperties", false)
	requireRequired(t, target, "os", "arch")
	for _, name := range []string{"os", "arch"} {
		if property(t, target, name)["minLength"] != float64(1) {
			t.Fatalf("target %s minLength = %v, want 1", name, property(t, target, name)["minLength"])
		}
	}

	supplementalArtifacts := property(t, parsed, "supplemental_artifacts")
	supplemental := asMap(t, supplementalArtifacts["items"], "release supplemental artifact")
	requireBool(t, supplemental, "additionalProperties", false)
	requireRequired(t, supplemental, "kind", "name", "path", "sha256", "size_bytes")
	requireEnum(t, property(t, supplemental, "kind"), "sbom", "provenance")
	for _, name := range []string{"name", "path"} {
		if property(t, supplemental, name)["minLength"] != float64(1) {
			t.Fatalf("supplemental %s minLength = %v, want 1", name, property(t, supplemental, name)["minLength"])
		}
	}
	requirePattern(t, property(t, supplemental, "sha256"))
	if property(t, supplemental, "size_bytes")["minimum"] != float64(1) {
		t.Fatalf("supplemental size_bytes minimum = %v, want 1", property(t, supplemental, "size_bytes")["minimum"])
	}
}

func TestReleasePackageResultSchemaDefinesStrictSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.release-package-result.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "manifest_path", "checksums_path", "artifact_paths", "manifest")
	if property(t, parsed, "schema_version")["const"] != ReleasePackageResultSchemaID {
		t.Fatalf("schema_version const = %v, want %s", property(t, parsed, "schema_version")["const"], ReleasePackageResultSchemaID)
	}
	for _, name := range []string{"manifest_path", "checksums_path"} {
		if property(t, parsed, name)["minLength"] != float64(1) {
			t.Fatalf("%s minLength = %v, want 1", name, property(t, parsed, name)["minLength"])
		}
	}
	artifactPaths := property(t, parsed, "artifact_paths")
	if artifactPaths["minItems"] != float64(1) {
		t.Fatalf("artifact_paths minItems = %v, want 1", artifactPaths["minItems"])
	}
	items := asMap(t, artifactPaths["items"], "release package artifact path")
	if items["minLength"] != float64(1) {
		t.Fatalf("artifact path minLength = %v, want 1", items["minLength"])
	}
	if property(t, parsed, "manifest")["$ref"] != ReleaseManifestSchemaID {
		t.Fatalf("manifest ref = %v, want %s", property(t, parsed, "manifest")["$ref"], ReleaseManifestSchemaID)
	}
}

func TestReleaseVerifyResultSchemaDefinesStrictSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.release-verify-result.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "verified", "manifest_path", "checksums_path", "artifact_count", "problems", "artifacts", "provenance")
	if property(t, parsed, "schema_version")["const"] != ReleaseVerifyResultSchemaID {
		t.Fatalf("schema_version const = %v, want %s", property(t, parsed, "schema_version")["const"], ReleaseVerifyResultSchemaID)
	}
	if property(t, parsed, "verified")["type"] != "boolean" {
		t.Fatalf("verified type = %v, want boolean", property(t, parsed, "verified")["type"])
	}
	for _, name := range []string{"manifest_path", "checksums_path"} {
		if property(t, parsed, name)["minLength"] != float64(1) {
			t.Fatalf("%s minLength = %v, want 1", name, property(t, parsed, name)["minLength"])
		}
	}
	if property(t, parsed, "artifact_count")["minimum"] != float64(0) {
		t.Fatalf("artifact_count minimum = %v, want 0", property(t, parsed, "artifact_count")["minimum"])
	}
	problems := property(t, parsed, "problems")
	items := asMap(t, problems["items"], "release verify problem")
	if items["minLength"] != float64(1) {
		t.Fatalf("problem minLength = %v, want 1", items["minLength"])
	}
	artifacts := property(t, parsed, "artifacts")
	artifact := asMap(t, artifacts["items"], "release verify artifact")
	requireBool(t, artifact, "additionalProperties", false)
	requireRequired(t, artifact, "name", "target", "path", "verified", "path_valid", "digest_verified", "size_verified", "checksum_verified", "metadata_verified", "host_metadata_checked", "sha256", "size_bytes", "actual_sha256", "actual_size_bytes", "problems")
	for _, name := range []string{"name", "path"} {
		if property(t, artifact, name)["minLength"] != float64(1) {
			t.Fatalf("artifact %s minLength = %v, want 1", name, property(t, artifact, name)["minLength"])
		}
	}
	requirePattern(t, property(t, artifact, "sha256"))
	if property(t, artifact, "actual_sha256")["type"] != "string" {
		t.Fatalf("artifact actual_sha256 type = %v, want string", property(t, artifact, "actual_sha256")["type"])
	}
	for _, name := range []string{"size_bytes", "actual_size_bytes"} {
		if property(t, artifact, name)["minimum"] != float64(0) {
			t.Fatalf("artifact %s minimum = %v, want 0", name, property(t, artifact, name)["minimum"])
		}
	}
	target := property(t, artifact, "target")
	requireBool(t, target, "additionalProperties", false)
	requireRequired(t, target, "os", "arch")
	artifactProblems := property(t, artifact, "problems")
	artifactProblem := asMap(t, artifactProblems["items"], "release verify artifact problem")
	if artifactProblem["minLength"] != float64(1) {
		t.Fatalf("artifact problem minLength = %v, want 1", artifactProblem["minLength"])
	}
	requireArtifactAttestationReportSchema(t, artifact)
	requireSupplementalArtifactReportSchema(t, parsed)
	provenance := property(t, parsed, "provenance")
	requireBool(t, provenance, "additionalProperties", false)
	requireRequired(t, provenance, "version", "commit", "date", "signature_verified", "artifacts")
	for _, name := range []string{"version", "commit", "date"} {
		if property(t, provenance, name)["minLength"] != float64(1) {
			t.Fatalf("provenance %s minLength = %v, want 1", name, property(t, provenance, name)["minLength"])
		}
	}
	provenanceArtifacts := property(t, provenance, "artifacts")
	provenanceArtifact := asMap(t, provenanceArtifacts["items"], "release provenance artifact")
	requireBool(t, provenanceArtifact, "additionalProperties", false)
	requireRequired(t, provenanceArtifact, "name", "target", "verification_status", "metadata_verified")
	requireEnum(t, property(t, provenanceArtifact, "verification_status"), "verified", "invalid")
	provenanceAttestations := property(t, provenanceArtifact, "attestations")
	provenanceAttestation := asMap(t, provenanceAttestations["items"], "release provenance attestation")
	requireBool(t, provenanceAttestation, "additionalProperties", false)
	requireRequired(t, provenanceAttestation, "name", "path", "verification_status", "sha256", "size_bytes")
	requireEnum(t, property(t, provenanceAttestation, "verification_status"), "verified", "invalid")
	for _, name := range []string{"kind", "name", "path"} {
		if property(t, provenanceAttestation, name)["minLength"] != float64(1) {
			t.Fatalf("provenance attestation %s minLength = %v, want 1", name, property(t, provenanceAttestation, name)["minLength"])
		}
	}
	requirePattern(t, property(t, provenanceAttestation, "sha256"))
	if property(t, provenanceAttestation, "size_bytes")["minimum"] != float64(0) {
		t.Fatalf("provenance attestation size_bytes minimum = %v, want 0", property(t, provenanceAttestation, "size_bytes")["minimum"])
	}
	binaryMetadata := property(t, provenanceArtifact, "binary_metadata")
	requireBool(t, binaryMetadata, "additionalProperties", false)
	requireRequired(t, binaryMetadata, "schema_version", "version", "commit", "date", "go_version", "os", "arch")
	provenanceSupplementals := property(t, provenance, "supplemental_artifacts")
	provenanceSupplemental := asMap(t, provenanceSupplementals["items"], "release provenance supplemental artifact")
	requireBool(t, provenanceSupplemental, "additionalProperties", false)
	requireRequired(t, provenanceSupplemental, "kind", "name", "path", "verification_status", "sha256", "size_bytes")
	requireEnum(t, property(t, provenanceSupplemental, "kind"), "sbom", "provenance")
	requireEnum(t, property(t, provenanceSupplemental, "verification_status"), "verified", "invalid")
	for _, name := range []string{"name", "path"} {
		if property(t, provenanceSupplemental, name)["minLength"] != float64(1) {
			t.Fatalf("provenance supplemental %s minLength = %v, want 1", name, property(t, provenanceSupplemental, name)["minLength"])
		}
	}
	requirePattern(t, property(t, provenanceSupplemental, "sha256"))
	if property(t, provenanceSupplemental, "size_bytes")["minimum"] != float64(0) {
		t.Fatalf("provenance supplemental size_bytes minimum = %v, want 0", property(t, provenanceSupplemental, "size_bytes")["minimum"])
	}
}

func TestReleaseDiffResultSchemaDefinesStrictSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.release-diff-result.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "from_dir", "to_dir", "changed", "redacted", "redactions", "entries")
	if property(t, parsed, "schema_version")["const"] != ReleaseDiffResultSchemaID {
		t.Fatalf("schema_version const = %v, want %s", property(t, parsed, "schema_version")["const"], ReleaseDiffResultSchemaID)
	}
	for _, name := range []string{"from_dir", "to_dir"} {
		if property(t, parsed, name)["minLength"] != float64(1) {
			t.Fatalf("%s minLength = %v, want 1", name, property(t, parsed, name)["minLength"])
		}
	}
	if property(t, parsed, "changed")["type"] != "boolean" {
		t.Fatalf("changed type = %v, want boolean", property(t, parsed, "changed")["type"])
	}
	if property(t, parsed, "redacted")["type"] != "boolean" {
		t.Fatalf("redacted type = %v, want boolean", property(t, parsed, "redacted")["type"])
	}
	redactions := property(t, parsed, "redactions")
	if redactions["type"] != "array" {
		t.Fatalf("redactions type = %v, want array", redactions["type"])
	}
	requireBool(t, redactions, "uniqueItems", true)
	requireEnum(t, asMap(t, redactions["items"], "release diff redactions items"), "paths", "digests")
	redactionProfile := property(t, parsed, "redaction_profile")
	if redactionProfile["type"] != "string" || redactionProfile["minLength"] != float64(1) {
		t.Fatalf("redaction_profile = %v, want non-empty string", redactionProfile)
	}
	entries := property(t, parsed, "entries")
	entry := asMap(t, entries["items"], "release diff entry")
	requireBool(t, entry, "additionalProperties", false)
	requireRequired(t, entry, "category", "action", "name", "detail")
	requireEnum(t, property(t, entry, "category"), "artifacts", "metadata", "problems", "signatures", "supplemental_artifacts")
	requireEnum(t, property(t, entry, "action"), "added", "changed", "present", "removed")
	for _, name := range []string{"name", "detail"} {
		if property(t, entry, name)["type"] != "string" {
			t.Fatalf("entry %s type = %v, want string", name, property(t, entry, name)["type"])
		}
	}
}

func TestReleaseSignatureSchemaDefinesStrictSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.release-signature.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "algorithm", "signed_entry", "public_key_sha256", "signature")
	if property(t, parsed, "schema_version")["const"] != ReleaseSignatureSchemaID {
		t.Fatalf("schema_version const = %v, want %s", property(t, parsed, "schema_version")["const"], ReleaseSignatureSchemaID)
	}
	if property(t, parsed, "algorithm")["const"] != "ed25519" {
		t.Fatalf("algorithm const = %v, want ed25519", property(t, parsed, "algorithm")["const"])
	}
	if property(t, parsed, "signed_entry")["const"] != "manifest.json" {
		t.Fatalf("signed_entry const = %v, want manifest.json", property(t, parsed, "signed_entry")["const"])
	}
	requirePattern(t, property(t, parsed, "public_key_sha256"))
	signature := property(t, parsed, "signature")
	if signature["minLength"] != float64(88) || signature["maxLength"] != float64(88) {
		t.Fatalf("signature length = min %v max %v, want 88/88", signature["minLength"], signature["maxLength"])
	}
}

func TestReleaseInspectResultSchemaDefinesStrictSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.release-inspect-result.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "release_dir", "manifest_path", "checksums_path", "manifest_valid", "checksum_status", "signature", "artifact_count", "artifacts", "problems")
	if property(t, parsed, "schema_version")["const"] != ReleaseInspectResultSchemaID {
		t.Fatalf("schema_version const = %v, want %s", property(t, parsed, "schema_version")["const"], ReleaseInspectResultSchemaID)
	}
	requireEnum(t, property(t, parsed, "checksum_status"), "verified", "invalid")
	signature := property(t, parsed, "signature")
	requireBool(t, signature, "additionalProperties", false)
	requireRequired(t, signature, "status")
	requireEnum(t, property(t, signature, "status"), "unsigned", "present_unverified", "verified", "invalid")
	artifacts := property(t, parsed, "artifacts")
	artifact := asMap(t, artifacts["items"], "release inspect artifact")
	requireBool(t, artifact, "additionalProperties", false)
	requireRequired(t, artifact, "name", "target", "path", "verified", "path_valid", "digest_verified", "size_verified", "checksum_verified", "metadata_verified", "host_metadata_checked", "sha256", "size_bytes", "actual_sha256", "actual_size_bytes", "problems")
	requireArtifactAttestationReportSchema(t, artifact)
	requireSupplementalArtifactReportSchema(t, parsed)
}

func TestReleaseReportResultSchemaDefinesStrictSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.release-report-result.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "valid", "format", "audience", "redacted", "redactions", "provenance_summary", "inspection")
	if property(t, parsed, "schema_version")["const"] != ReleaseReportResultSchemaID {
		t.Fatalf("schema_version const = %v, want %s", property(t, parsed, "schema_version")["const"], ReleaseReportResultSchemaID)
	}
	if property(t, parsed, "format")["const"] != "json" {
		t.Fatalf("format const = %v, want json", property(t, parsed, "format")["const"])
	}
	requireEnum(t, property(t, parsed, "audience"), "internal", "external")
	redactions := property(t, parsed, "redactions")
	if redactions["type"] != "array" {
		t.Fatalf("redactions type = %v, want array", redactions["type"])
	}
	requireBool(t, redactions, "uniqueItems", true)
	requireEnum(t, asMap(t, redactions["items"], "redactions items"), "paths", "digests")
	redactionProfile := property(t, parsed, "redaction_profile")
	if redactionProfile["type"] != "string" || redactionProfile["minLength"] != float64(1) {
		t.Fatalf("redaction_profile = %v, want non-empty string", redactionProfile)
	}
	provenanceSummary := property(t, parsed, "provenance_summary")
	requireBool(t, provenanceSummary, "additionalProperties", false)
	requireRequired(t, provenanceSummary, "signature_status", "attestation_verified_count", "attestation_invalid_count", "sbom_verified_count", "sbom_invalid_count", "supplemental_provenance_verified_count", "supplemental_provenance_invalid_count", "invalid_evidence_count")
	requireEnum(t, property(t, provenanceSummary, "signature_status"), "unsigned", "present_unverified", "verified", "invalid")
	for _, name := range []string{
		"attestation_verified_count",
		"attestation_invalid_count",
		"sbom_verified_count",
		"sbom_invalid_count",
		"supplemental_provenance_verified_count",
		"supplemental_provenance_invalid_count",
		"invalid_evidence_count",
	} {
		if property(t, provenanceSummary, name)["type"] != "integer" || property(t, provenanceSummary, name)["minimum"] != float64(0) {
			t.Fatalf("provenance_summary %s = %v, want non-negative integer", name, property(t, provenanceSummary, name))
		}
	}
	inspection := property(t, parsed, "inspection")
	if inspection["$ref"] != ReleaseInspectResultSchemaID {
		t.Fatalf("inspection ref = %v, want %s", inspection["$ref"], ReleaseInspectResultSchemaID)
	}
}

func TestReleaseJSONFixturesValidateAgainstPublishedSchemas(t *testing.T) {
	fixtures := []struct {
		schemaID string
		fileName string
	}{
		{ReleasePackageResultSchemaID, "release-package-result.json"},
		{ReleaseVerifyResultSchemaID, "release-verify-result.json"},
		{ReleaseInspectResultSchemaID, "release-inspect-result.json"},
		{ReleaseInspectResultSchemaID, "release-inspect-result-redacted.json"},
		{ReleaseReportResultSchemaID, "release-report-result.json"},
		{ReleaseReportResultSchemaID, "release-report-result-redacted.json"},
		{ReleaseDiffResultSchemaID, "release-diff-result.json"},
		{ReleaseDiffResultSchemaID, "release-diff-result-redacted.json"},
		{ReleaseSignatureSchemaID, "release-signature.json"},
	}

	for _, fixture := range fixtures {
		t.Run(fixture.schemaID, func(t *testing.T) {
			data := readReleaseFixture(t, fixture.fileName)
			if err := ValidateBytes(fixture.schemaID, data); err != nil {
				t.Fatalf("%s did not validate against %s: %v\njson:\n%s", fixture.fileName, fixture.schemaID, err, string(data))
			}

			var decoded map[string]any
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("decode fixture %s: %v", fixture.fileName, err)
			}
			if decoded["schema_version"] != fixture.schemaID {
				t.Fatalf("%s schema_version = %v, want %s", fixture.fileName, decoded["schema_version"], fixture.schemaID)
			}
		})
	}
}

func TestReleaseJSONFixturesCoverCatalogedReleaseResultSchemas(t *testing.T) {
	expected := map[string]string{
		ReleasePackageResultSchemaID: "release-package-result.json",
		ReleaseVerifyResultSchemaID:  "release-verify-result.json",
		ReleaseInspectResultSchemaID: "release-inspect-result.json",
		ReleaseReportResultSchemaID:  "release-report-result.json",
		ReleaseDiffResultSchemaID:    "release-diff-result.json",
		ReleaseSignatureSchemaID:     "release-signature.json",
	}
	additionalFixtures := []string{
		"release-inspect-result-redacted.json",
		"release-report-result-redacted.json",
		"release-diff-result-redacted.json",
	}
	expectedFiles := make(map[string]bool, len(expected))

	for schemaID, fileName := range expected {
		expectedFiles[fileName] = true
		required, ok := RequiredSchemaByID(schemaID)
		if !ok {
			t.Fatalf("fixture schema %s is not cataloged", schemaID)
		}
		if required.SchemaPath != schemaTestPath(required.FileName) {
			t.Fatalf("%s schema path = %q, want schemas/%s", schemaID, required.SchemaPath, required.FileName)
		}
		if len(readReleaseFixture(t, fileName)) == 0 {
			t.Fatalf("fixture %s is empty", fileName)
		}
	}
	for _, fileName := range additionalFixtures {
		expectedFiles[fileName] = true
		if len(readReleaseFixture(t, fileName)) == 0 {
			t.Fatalf("fixture %s is empty", fileName)
		}
	}

	entries, err := os.ReadDir(filepath.Join("testdata", "release-fixtures"))
	if err != nil {
		t.Fatalf("read release fixture dir: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatalf("unexpected release fixture directory %s", entry.Name())
		}
		if !expectedFiles[entry.Name()] {
			t.Fatalf("unexpected release fixture file %s", entry.Name())
		}
	}
}

func TestReleaseRedactedJSONFixturesUseStableRedactionTokens(t *testing.T) {
	tests := []struct {
		fileName          string
		schemaID          string
		wantMetadata      bool
		wantDigestToken   string
		forbiddenContents []string
	}{
		{
			fileName:        "release-inspect-result-redacted.json",
			schemaID:        ReleaseInspectResultSchemaID,
			wantDigestToken: strings.Repeat("0", 64),
			forbiddenContents: []string{
				"dist/manifest.json",
				"dist/checksums.txt",
				"dist/manifest.sig.json",
				"1111111111111111111111111111111111111111111111111111111111111111",
				"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		},
		{
			fileName:        "release-report-result-redacted.json",
			schemaID:        ReleaseReportResultSchemaID,
			wantMetadata:    true,
			wantDigestToken: strings.Repeat("0", 64),
			forbiddenContents: []string{
				"dist/manifest.json",
				"dist/checksums.txt",
				"dist/manifest.sig.json",
				"1111111111111111111111111111111111111111111111111111111111111111",
				"2222222222222222222222222222222222222222222222222222222222222222",
				"4444444444444444444444444444444444444444444444444444444444444444",
				"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		},
		{
			fileName:        "release-diff-result-redacted.json",
			schemaID:        ReleaseDiffResultSchemaID,
			wantMetadata:    true,
			wantDigestToken: "[REDACTED_DIGEST]",
			forbiddenContents: []string{
				"dist-v0.1.0",
				"dist-v0.2.0",
				"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.fileName, func(t *testing.T) {
			data := readReleaseFixture(t, tt.fileName)
			if err := ValidateBytes(tt.schemaID, data); err != nil {
				t.Fatalf("%s did not validate against %s: %v\njson:\n%s", tt.fileName, tt.schemaID, err, string(data))
			}
			text := string(data)
			if !strings.Contains(text, "[REDACTED_PATH]") {
				t.Fatalf("%s = %s, want [REDACTED_PATH]", tt.fileName, text)
			}
			if !strings.Contains(text, tt.wantDigestToken) {
				t.Fatalf("%s = %s, want digest token %q", tt.fileName, text, tt.wantDigestToken)
			}
			if tt.wantMetadata {
				for _, want := range []string{`"redacted": true`, `"redactions":`, `"redaction_profile": "partner"`} {
					if !strings.Contains(text, want) {
						t.Fatalf("%s = %s, want %s", tt.fileName, text, want)
					}
				}
			}
			if tt.fileName == "release-report-result-redacted.json" {
				for _, want := range []string{
					`"attestation_verified_count": 1`,
					`"sbom_verified_count": 1`,
					`"supplemental_provenance_verified_count": 1`,
					`"invalid_evidence_count": 0`,
				} {
					if !strings.Contains(text, want) {
						t.Fatalf("%s = %s, want provenance count %s", tt.fileName, text, want)
					}
				}
			}
			for _, forbidden := range tt.forbiddenContents {
				if strings.Contains(text, forbidden) {
					t.Fatalf("%s = %s, want %q redacted", tt.fileName, text, forbidden)
				}
			}
		})
	}
}

func TestBundleInspectResultSchemaDefinesStrictInspectionSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.bundle-inspect-result.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "bundle_path", "run_id", "contract_digest", "ledger_digest", "entry_count", "checksum_status", "signature", "verification", "event_count", "artifact_count", "input_snapshot_count", "policy_decision_count", "closure_row_count", "failure_count", "revocation_list_count", "revoked_ticket_count", "entries", "artifacts", "input_snapshots", "policy_explanations")

	if property(t, parsed, "schema_version")["const"] != BundleInspectResultSchemaID {
		t.Fatalf("schema_version const = %v, want %s", property(t, parsed, "schema_version")["const"], BundleInspectResultSchemaID)
	}

	requireEnum(t, property(t, parsed, "checksum_status"), "verified")
	signature := property(t, parsed, "signature")
	requireBool(t, signature, "additionalProperties", false)
	requireRequired(t, signature, "status")
	requireEnum(t, property(t, signature, "status"), "unsigned", "present_unverified", "verified")

	entries := property(t, parsed, "entries")
	entry := asMap(t, entries["items"], "bundle inspect entry")
	requireBool(t, entry, "additionalProperties", false)
	requireRequired(t, entry, "path", "source", "sha256", "size_bytes")

	artifacts := property(t, parsed, "artifacts")
	artifact := asMap(t, artifacts["items"], "bundle inspect artifact")
	requireBool(t, artifact, "additionalProperties", false)
	requireRequired(t, artifact, "artifact_id", "path", "digest", "media_type", "producer_event_id", "producer_found")

	policyExplanations := property(t, parsed, "policy_explanations")
	explanation := asMap(t, policyExplanations["items"], "bundle inspect policy explanation")
	requireBool(t, explanation, "additionalProperties", false)
	requireRequired(t, explanation, "decision_id", "task_id", "effect_type", "resource", "decision", "reason", "summary", "detail")
}

func TestBundleReportResultSchemaDefinesStrictReportSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.bundle-report-result.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "bundle_path", "run_id", "contract_digest", "ledger_digest", "entry_count", "checksum_status", "signature", "verification", "event_count", "artifact_count", "input_snapshot_count", "policy_decision_count", "closure_row_count", "failure_count", "revocation_list_count", "revoked_ticket_count", "entries", "events", "artifacts", "input_snapshots", "policy_decisions", "policy_explanations", "failures", "closure_rows")

	if property(t, parsed, "schema_version")["const"] != BundleReportResultSchemaID {
		t.Fatalf("schema_version const = %v, want %s", property(t, parsed, "schema_version")["const"], BundleReportResultSchemaID)
	}

	requireEnum(t, property(t, parsed, "checksum_status"), "verified")
	signature := property(t, parsed, "signature")
	requireBool(t, signature, "additionalProperties", false)
	requireRequired(t, signature, "status")
	requireEnum(t, property(t, signature, "status"), "unsigned", "present_unverified", "verified")

	events := property(t, parsed, "events")
	event := asMap(t, events["items"], "bundle report event")
	requireBool(t, event, "additionalProperties", false)
	requireRequired(t, event, "event_id", "sequence", "line", "type", "status")
	requireEnum(t, property(t, event, "type"), "run_started", "task_started", "policy_decided", "artifact_recorded", "task_finished", "run_finished")

	policyDecisions := property(t, parsed, "policy_decisions")
	requireRef(t, asMap(t, policyDecisions["items"], "bundle report policy decision"), "covenant.policy-decision.v1")

	failures := property(t, parsed, "failures")
	failure := asMap(t, failures["items"], "bundle report failure")
	requireBool(t, failure, "additionalProperties", false)
	requireRequired(t, failure, "failure_id", "event_id", "event_line", "event_found", "phase", "reason")

	closureRows := property(t, parsed, "closure_rows")
	closureRow := asMap(t, closureRows["items"], "bundle report closure row")
	requireBool(t, closureRow, "additionalProperties", false)
	requireRequired(t, closureRow, "obligation_id", "required", "status", "task_ids", "artifact_ids", "missing_artifact_ids", "policy_decision_ids", "missing_policy_decision_ids", "reason")
	requireEnum(t, property(t, closureRow, "status"), "closed", "open")
}

func TestInputSnapshotSchemaDefinesStrictSnapshotSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.input-snapshot.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "snapshot_id", "source_path", "snapshot_path", "digest", "media_type")
	requirePattern(t, property(t, parsed, "snapshot_id"))
	requirePattern(t, property(t, parsed, "source_path"))
	requirePattern(t, property(t, parsed, "snapshot_path"))
	requirePattern(t, property(t, parsed, "digest"))
}

func TestArtifactRefSchemaDefinesRunnerSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.artifact-ref.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "artifact_id", "uri", "digest", "media_type", "producer_event_id", "path")
	if _, ok := property(t, parsed, "path")["pattern"]; !ok {
		t.Fatalf("artifact path missing pattern")
	}
}

func TestPolicyDecisionSchemaDefinesStrictDecisionSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.policy-decision.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "decision_id", "task_id", "effect_type", "resource", "decision", "reason")
	requirePattern(t, property(t, parsed, "decision_id"))
	requirePattern(t, property(t, parsed, "task_id"))
	requirePattern(t, property(t, parsed, "resource"))
	effectType := property(t, parsed, "effect_type")
	requireEnum(t, effectType, "file.write", "file.read", "process.spawn", "network.request")
	decision := property(t, parsed, "decision")
	requireEnum(t, decision, "allow", "deny")
}

func TestClosureMatrixSchemaDefinesStrictClosureSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.closure-matrix.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "run_id", "contract_digest", "status", "rows")
	requirePattern(t, property(t, parsed, "run_id"))

	status := property(t, parsed, "status")
	requireEnum(t, status, "accepted", "rejected")

	rows := property(t, parsed, "rows")
	row := asMap(t, rows["items"], "closure row")
	requireBool(t, row, "additionalProperties", false)
	requireRequired(t, row, "obligation_id", "required", "status", "task_ids", "artifact_ids", "policy_decision_ids", "reason")
	rowStatus := property(t, row, "status")
	requireEnum(t, rowStatus, "closed", "open")
}

func TestFailureSchemaDefinesFailureEvidenceSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.failure.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "failure_id", "event_id", "phase", "reason")
	requirePattern(t, property(t, parsed, "failure_id"))
	requirePattern(t, property(t, parsed, "event_id"))
	requirePattern(t, property(t, parsed, "task_id"))
	phase := property(t, parsed, "phase")
	requireEnum(t, phase, "policy", "adapter", "execution", "closure")
}

func TestReportRedactionPolicySchemaDefinesStrictProfileSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.report-redaction-policy.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "profiles")

	profiles := property(t, parsed, "profiles")
	requireBool(t, profiles, "additionalProperties", false)
	if profiles["minProperties"] != float64(1) {
		t.Fatalf("profiles minProperties = %v, want 1", profiles["minProperties"])
	}
	patternProperties := asMap(t, profiles["patternProperties"], "profiles patternProperties")
	profile := asMap(t, patternProperties["^[a-z0-9][a-z0-9_-]*$"], "redaction profile")
	requireBool(t, profile, "additionalProperties", false)
	requireRequired(t, profile, "redact")

	redact := property(t, profile, "redact")
	if redact["minItems"] != float64(1) {
		t.Fatalf("redact minItems = %v, want 1", redact["minItems"])
	}
	items := asMap(t, redact["items"], "redact items")
	requireEnum(t, items, "paths", "digests")
}

func TestReleaseFixtureIndexSchemaDefinesStrictFixtureSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.release-fixture-index.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "fixtures")
	if property(t, parsed, "schema_version")["const"] != ReleaseFixtureIndexSchemaID {
		t.Fatalf("schema_version const = %v, want %s", property(t, parsed, "schema_version")["const"], ReleaseFixtureIndexSchemaID)
	}

	fixtures := property(t, parsed, "fixtures")
	if fixtures["minItems"] != float64(1) {
		t.Fatalf("fixtures minItems = %v, want 1", fixtures["minItems"])
	}
	fixture := asMap(t, fixtures["items"], "fixture index item")
	requireBool(t, fixture, "additionalProperties", false)
	requireRequired(t, fixture, "name", "directory", "purpose", "generated", "check_command", "files")
	for _, name := range []string{"name", "directory", "purpose", "check_command", "refresh_command"} {
		if property(t, fixture, name)["minLength"] != float64(1) {
			t.Fatalf("fixture %s minLength = %v, want 1", name, property(t, fixture, name)["minLength"])
		}
	}
	if property(t, fixture, "generated")["type"] != "boolean" {
		t.Fatalf("generated type = %v, want boolean", property(t, fixture, "generated")["type"])
	}
	files := property(t, fixture, "files")
	if files["minItems"] != float64(1) || files["uniqueItems"] != true {
		t.Fatalf("files constraints = %+v, want minItems 1 uniqueItems true", files)
	}
	file := asMap(t, files["items"], "fixture file")
	if file["minLength"] != float64(1) {
		t.Fatalf("file minLength = %v, want 1", file["minLength"])
	}
}

func TestReleaseFixtureIndexSchemaRejectsInvalidFixtureDocuments(t *testing.T) {
	valid := `{
	  "schema_version": "covenant.release-fixture-index.v1",
	  "fixtures": [
	    {
	      "name": "release-json",
	      "directory": "internal/schema/testdata/release-fixtures",
	      "purpose": "Stable release JSON fixtures.",
	      "generated": true,
	      "refresh_command": "COVENANT_UPDATE_RELEASE_FIXTURES=1 go test ./internal/release -run ReleaseJSONFixturesMatchGeneratedGoldenFiles -count=1",
	      "check_command": "go test ./internal/schema -run ReleaseJSONFixtures -count=1",
	      "files": ["release-package-result.json", "release-verify-result.json"]
	    }
	  ]
	}`
	tests := []struct {
		name string
		json string
		want string
	}{
		{
			name: "duplicate files",
			json: strings.Replace(valid, `"files": ["release-package-result.json", "release-verify-result.json"]`, `"files": ["release-package-result.json", "release-package-result.json"]`, 1),
			want: "items at 0 and 1 are equal",
		},
		{
			name: "unknown root property",
			json: strings.Replace(valid, `"fixtures": [`, `"unexpected": true, "fixtures": [`, 1),
			want: "additional properties 'unexpected' not allowed",
		},
		{
			name: "unknown fixture property",
			json: strings.Replace(valid, `"files": [`, `"unexpected": true, "files": [`, 1),
			want: "additional properties 'unexpected' not allowed",
		},
		{
			name: "empty check command",
			json: strings.Replace(valid, `"check_command": "go test ./internal/schema -run ReleaseJSONFixtures -count=1"`, `"check_command": ""`, 1),
			want: "minLength",
		},
		{
			name: "empty refresh command",
			json: strings.Replace(valid, `"refresh_command": "COVENANT_UPDATE_RELEASE_FIXTURES=1 go test ./internal/release -run ReleaseJSONFixturesMatchGeneratedGoldenFiles -count=1"`, `"refresh_command": ""`, 1),
			want: "minLength",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBytes(ReleaseFixtureIndexSchemaID, []byte(tt.json))
			if err == nil {
				t.Fatalf("ValidateBytes accepted invalid fixture index")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %q, want %q", err.Error(), tt.want)
			}
		})
	}
}

func TestLintSARIFBaselineSchemaDefinesStrictAcceptedSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.lint-sarif-baseline.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "accepted")

	accepted := property(t, parsed, "accepted")
	items := asMap(t, accepted["items"], "accepted items")
	requireBool(t, items, "additionalProperties", false)
	requireRequired(t, items, "rule_id", "justification")
	requirePattern(t, property(t, items, "rule_id"))
	if property(t, items, "source_uri")["minLength"] != float64(1) {
		t.Fatalf("source_uri minLength = %v, want 1", property(t, items, "source_uri")["minLength"])
	}
	if property(t, items, "line")["minimum"] != float64(1) {
		t.Fatalf("line minimum = %v, want 1", property(t, items, "line")["minimum"])
	}
	if property(t, items, "field")["minLength"] != float64(1) {
		t.Fatalf("field minLength = %v, want 1", property(t, items, "field")["minLength"])
	}
	if property(t, items, "justification")["minLength"] != float64(1) {
		t.Fatalf("justification minLength = %v, want 1", property(t, items, "justification")["minLength"])
	}
}

func TestLintResultSchemaDefinesStrictLintSurface(t *testing.T) {
	parsed := readSchema(t, "covenant.lint-result.v1.schema.json")
	requireBool(t, parsed, "additionalProperties", false)
	requireRequired(t, parsed, "schema_version", "valid", "diagnostics")

	if property(t, parsed, "schema_version")["const"] != LintResultSchemaID {
		t.Fatalf("schema_version const = %v, want %s", property(t, parsed, "schema_version")["const"], LintResultSchemaID)
	}

	diagnostics := property(t, parsed, "diagnostics")
	diagnostic := asMap(t, diagnostics["items"], "lint diagnostic")
	requireBool(t, diagnostic, "additionalProperties", false)
	requireRequired(t, diagnostic, "code", "severity", "message")
	requirePattern(t, property(t, diagnostic, "code"))
	requireEnum(t, property(t, diagnostic, "severity"), "error", "warning", "info")
	if property(t, diagnostic, "line")["minimum"] != float64(1) {
		t.Fatalf("line minimum = %v, want 1", property(t, diagnostic, "line")["minimum"])
	}
	if property(t, diagnostic, "field")["minLength"] != float64(1) {
		t.Fatalf("field minLength = %v, want 1", property(t, diagnostic, "field")["minLength"])
	}
	if property(t, diagnostic, "hint")["minLength"] != float64(1) {
		t.Fatalf("hint minLength = %v, want 1", property(t, diagnostic, "hint")["minLength"])
	}
}

func TestValidateValueAcceptsValidContractDocument(t *testing.T) {
	if err := ValidateValue(ContractSchemaID, validContractDocument()); err != nil {
		t.Fatalf("ValidateValue returned error: %v", err)
	}
}

func TestValidateValueRejectsAdditionalContractProperty(t *testing.T) {
	document := validContractDocument()
	document["unexpected"] = true

	err := ValidateValue(ContractSchemaID, document)
	if err == nil {
		t.Fatalf("ValidateValue returned nil, want schema error")
	}
	if !strings.Contains(err.Error(), "schema validation failed for covenant.contract.v1") {
		t.Fatalf("ValidateValue error = %v, want schema validation context", err)
	}
}

func TestValidateValueAcceptsValidTaskDocument(t *testing.T) {
	document := validTaskDocument()

	if err := ValidateValue(TaskSchemaID, document); err != nil {
		t.Fatalf("ValidateValue returned error: %v", err)
	}
}

func TestValidateValueRejectsTaskMissingDependsOn(t *testing.T) {
	document := validTaskDocument()
	delete(document, "depends_on")

	err := ValidateValue(TaskSchemaID, document)
	if err == nil {
		t.Fatalf("ValidateValue returned nil, want schema error")
	}
	if !strings.Contains(err.Error(), "schema validation failed for covenant.task.v1") {
		t.Fatalf("ValidateValue error = %v, want task schema context", err)
	}
}

func TestValidateValueRejectsTaskInvalidSideEffectResource(t *testing.T) {
	document := validTaskDocument()
	document["declared_side_effects"] = []any{
		map[string]any{"type": "file.write", "resource": "../outside.txt"},
	}

	err := ValidateValue(TaskSchemaID, document)
	if err == nil {
		t.Fatalf("ValidateValue returned nil, want schema error")
	}
	if !strings.Contains(err.Error(), "schema validation failed for covenant.task.v1") {
		t.Fatalf("ValidateValue error = %v, want task schema context", err)
	}
}

func TestValidateValueAcceptsValidPolicyEvent(t *testing.T) {
	document := validEventDocument("policy_decided")
	document["task_id"] = "scripted_change"
	document["status"] = "success"
	document["message"] = "allowed"
	document["decision_id"] = "policy-scripted_change-1"
	document["decision"] = "allow"
	document["effect_type"] = "file.write"
	document["resource"] = "demo-output/report.txt"

	if err := ValidateValue(EventSchemaID, document); err != nil {
		t.Fatalf("ValidateValue returned error: %v", err)
	}
}

func TestValidateValueRejectsPolicyEventMissingDecisionID(t *testing.T) {
	document := validEventDocument("policy_decided")
	document["task_id"] = "scripted_change"
	document["status"] = "success"
	document["message"] = "allowed"
	document["decision"] = "allow"
	document["effect_type"] = "file.write"
	document["resource"] = "demo-output/report.txt"

	err := ValidateValue(EventSchemaID, document)
	if err == nil {
		t.Fatalf("ValidateValue returned nil, want schema error")
	}
	if !strings.Contains(err.Error(), "schema validation failed for covenant.event.v1") {
		t.Fatalf("ValidateValue error = %v, want event schema context", err)
	}
}

func TestValidateValueRejectsNonPolicyEventWithPolicyFields(t *testing.T) {
	document := validEventDocument("task_started")
	document["task_id"] = "scripted_change"
	document["decision_id"] = "policy-scripted_change-1"

	err := ValidateValue(EventSchemaID, document)
	if err == nil {
		t.Fatalf("ValidateValue returned nil, want schema error")
	}
	if !strings.Contains(err.Error(), "schema validation failed for covenant.event.v1") {
		t.Fatalf("ValidateValue error = %v, want event schema context", err)
	}
}

func TestValidateValueRejectsInvalidEvidenceDigest(t *testing.T) {
	document := validEvidencePackDocument()
	document["ledger_digest"] = "not-a-sha"

	err := ValidateValue(EvidencePackSchemaID, document)
	if err == nil {
		t.Fatalf("ValidateValue returned nil, want schema error")
	}
	if !strings.Contains(err.Error(), "schema validation failed for covenant.evidence-pack.v1") {
		t.Fatalf("ValidateValue error = %v, want schema validation context", err)
	}
}

func TestValidateValueAcceptsValidEvidenceBundleManifest(t *testing.T) {
	document := validEvidenceBundleManifestDocument()

	if err := ValidateValue(EvidenceBundleSchemaID, document); err != nil {
		t.Fatalf("ValidateValue returned error: %v", err)
	}
}

func TestValidateValueRejectsBundleManifestExtraEntryProperty(t *testing.T) {
	document := validEvidenceBundleManifestDocument()
	entries := document["entries"].([]any)
	entries[0].(map[string]any)["unexpected"] = "value"

	err := ValidateValue(EvidenceBundleSchemaID, document)
	if err == nil {
		t.Fatalf("ValidateValue returned nil, want schema error")
	}
	if !strings.Contains(err.Error(), "schema validation failed for covenant.evidence-bundle.v1") {
		t.Fatalf("ValidateValue error = %v, want bundle schema context", err)
	}
}

func TestValidateValueRejectsInvalidApprovalRevocationTicketID(t *testing.T) {
	document := map[string]any{
		"schema_version": "covenant.approval-revocations.v1",
		"revoked_tickets": []any{
			map[string]any{
				"ticket_id": "Bad Ticket",
				"reason":    "operator revoked bad ticket",
			},
		},
	}

	err := ValidateValue(ApprovalRevocationsSchemaID, document)
	if err == nil {
		t.Fatalf("ValidateValue returned nil, want schema error")
	}
	if !strings.Contains(err.Error(), "schema validation failed for covenant.approval-revocations.v1") {
		t.Fatalf("ValidateValue error = %v, want approval revocations schema context", err)
	}
}

func TestValidateValueAcceptsValidFailureRecord(t *testing.T) {
	document := map[string]any{
		"schema_version": "covenant.failure.v1",
		"failure_id":     "failure-000001",
		"event_id":       "event-000004",
		"task_id":        "scripted_change",
		"phase":          "adapter",
		"reason":         "no default adapter for process.spawn",
	}

	if err := ValidateValue(FailureSchemaID, document); err != nil {
		t.Fatalf("ValidateValue returned error: %v", err)
	}
}

func TestValidateValueAcceptsValidReportRedactionPolicy(t *testing.T) {
	document := map[string]any{
		"schema_version": "covenant.report-redaction-policy.v1",
		"profiles": map[string]any{
			"external": map[string]any{
				"redact": []any{"paths", "digests"},
			},
		},
	}

	if err := ValidateValue(ReportRedactionPolicySchemaID, document); err != nil {
		t.Fatalf("ValidateValue returned error: %v", err)
	}
}

func TestValidateValueRejectsInvalidReportRedactionPolicyRedactValue(t *testing.T) {
	document := map[string]any{
		"schema_version": "covenant.report-redaction-policy.v1",
		"profiles": map[string]any{
			"external": map[string]any{
				"redact": []any{"paths", "secrets"},
			},
		},
	}

	err := ValidateValue(ReportRedactionPolicySchemaID, document)
	if err == nil {
		t.Fatalf("ValidateValue returned nil, want schema error")
	}
	if !strings.Contains(err.Error(), "schema validation failed for covenant.report-redaction-policy.v1") {
		t.Fatalf("ValidateValue error = %v, want report redaction policy schema context", err)
	}
}

func TestValidateValueAcceptsValidLintSARIFBaseline(t *testing.T) {
	document := map[string]any{
		"schema_version": "covenant.lint-sarif-baseline.v1",
		"accepted": []any{
			map[string]any{
				"rule_id":       "STRUCTURED_TASK_FIELD_UNKNOWN",
				"source_uri":    "examples/structured-release/brief.md",
				"line":          float64(8),
				"field":         "tasks.writes",
				"justification": "accepted until the source brief is migrated",
			},
		},
	}

	if err := ValidateValue(LintSARIFBaselineSchemaID, document); err != nil {
		t.Fatalf("ValidateValue returned error: %v", err)
	}
}

func TestValidateValueRejectsInvalidLintSARIFBaselineExtraProperty(t *testing.T) {
	document := map[string]any{
		"schema_version": "covenant.lint-sarif-baseline.v1",
		"accepted": []any{
			map[string]any{
				"rule_id":       "STRUCTURED_TASK_FIELD_UNKNOWN",
				"justification": "accepted until the source brief is migrated",
				"expires_after": "2026-07-01",
			},
		},
	}

	err := ValidateValue(LintSARIFBaselineSchemaID, document)
	if err == nil {
		t.Fatalf("ValidateValue returned nil, want schema error")
	}
	if !strings.Contains(err.Error(), "schema validation failed for covenant.lint-sarif-baseline.v1") {
		t.Fatalf("ValidateValue error = %v, want lint sarif baseline schema context", err)
	}
}

func readSchema(t *testing.T, fileName string) map[string]any {
	t.Helper()
	path := filepath.Join("..", "..", "schemas", fileName)
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(bytes, &parsed); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return parsed
}

func readReleaseFixture(t *testing.T, fileName string) []byte {
	t.Helper()
	path := filepath.Join("testdata", "release-fixtures", fileName)
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return bytes
}

func requireArtifactAttestationReportSchema(t *testing.T, artifact map[string]any) {
	t.Helper()
	attestations := property(t, artifact, "attestations")
	attestation := asMap(t, attestations["items"], "release artifact attestation report")
	requireBool(t, attestation, "additionalProperties", false)
	requireRequired(t, attestation, "name", "path", "verified", "path_valid", "digest_verified", "size_verified", "checksum_verified", "sha256", "size_bytes", "actual_sha256", "actual_size_bytes", "problems")
	for _, name := range []string{"name", "kind", "path"} {
		if property(t, attestation, name)["minLength"] != float64(1) {
			t.Fatalf("attestation report %s minLength = %v, want 1", name, property(t, attestation, name)["minLength"])
		}
	}
	requirePattern(t, property(t, attestation, "sha256"))
	for _, name := range []string{"size_bytes", "actual_size_bytes"} {
		if property(t, attestation, name)["minimum"] != float64(0) {
			t.Fatalf("attestation report %s minimum = %v, want 0", name, property(t, attestation, name)["minimum"])
		}
	}
	problems := property(t, attestation, "problems")
	problem := asMap(t, problems["items"], "release artifact attestation problem")
	if problem["minLength"] != float64(1) {
		t.Fatalf("attestation report problem minLength = %v, want 1", problem["minLength"])
	}
}

func requireSupplementalArtifactReportSchema(t *testing.T, schema map[string]any) {
	t.Helper()
	supplementalArtifacts := property(t, schema, "supplemental_artifacts")
	supplemental := asMap(t, supplementalArtifacts["items"], "release supplemental artifact report")
	requireBool(t, supplemental, "additionalProperties", false)
	requireRequired(t, supplemental, "kind", "name", "path", "verified", "path_valid", "digest_verified", "size_verified", "checksum_verified", "sha256", "size_bytes", "actual_sha256", "actual_size_bytes", "problems")
	requireEnum(t, property(t, supplemental, "kind"), "sbom", "provenance")
	for _, name := range []string{"name", "path"} {
		if property(t, supplemental, name)["minLength"] != float64(1) {
			t.Fatalf("supplemental report %s minLength = %v, want 1", name, property(t, supplemental, name)["minLength"])
		}
	}
	requirePattern(t, property(t, supplemental, "sha256"))
	for _, name := range []string{"size_bytes", "actual_size_bytes"} {
		if property(t, supplemental, name)["minimum"] != float64(0) {
			t.Fatalf("supplemental report %s minimum = %v, want 0", name, property(t, supplemental, name)["minimum"])
		}
	}
	problems := property(t, supplemental, "problems")
	problem := asMap(t, problems["items"], "release supplemental artifact problem")
	if problem["minLength"] != float64(1) {
		t.Fatalf("supplemental report problem minLength = %v, want 1", problem["minLength"])
	}
}

func property(t *testing.T, schema map[string]any, name string) map[string]any {
	t.Helper()
	properties := asMap(t, schema["properties"], "properties")
	value, ok := properties[name]
	if !ok {
		t.Fatalf("schema missing property %q", name)
	}
	return asMap(t, value, name)
}

func asMap(t *testing.T, value any, label string) map[string]any {
	t.Helper()
	m, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s = %T, want object", label, value)
	}
	return m
}

func requireBool(t *testing.T, schema map[string]any, key string, want bool) {
	t.Helper()
	got, ok := schema[key].(bool)
	if !ok || got != want {
		t.Fatalf("%s = %v, want %v", key, schema[key], want)
	}
}

func requireRequired(t *testing.T, schema map[string]any, names ...string) {
	t.Helper()
	required, ok := schema["required"].([]any)
	if !ok {
		t.Fatalf("required = %T, want array", schema["required"])
	}
	seen := map[string]bool{}
	for _, value := range required {
		s, ok := value.(string)
		if !ok {
			t.Fatalf("required entry = %T, want string", value)
		}
		seen[s] = true
	}
	for _, name := range names {
		if !seen[name] {
			t.Fatalf("required missing %q in %v", name, required)
		}
	}
}

func requireRef(t *testing.T, schema map[string]any, want string) {
	t.Helper()
	got, ok := schema["$ref"].(string)
	if !ok || got != want {
		t.Fatalf("$ref = %v, want %s", schema["$ref"], want)
	}
}

func requirePattern(t *testing.T, schema map[string]any) {
	t.Helper()
	if _, ok := schema["pattern"].(string); !ok {
		t.Fatalf("pattern = %v, want string pattern", schema["pattern"])
	}
}

func requireEnum(t *testing.T, schema map[string]any, names ...string) {
	t.Helper()
	values, ok := schema["enum"].([]any)
	if !ok {
		t.Fatalf("enum = %T, want array", schema["enum"])
	}
	seen := map[string]bool{}
	for _, value := range values {
		s, ok := value.(string)
		if !ok {
			t.Fatalf("enum entry = %T, want string", value)
		}
		seen[s] = true
	}
	for _, name := range names {
		if !seen[name] {
			t.Fatalf("enum missing %q in %v", name, values)
		}
	}
}

func validEventDocument(eventType string) map[string]any {
	return map[string]any{
		"schema_version":      "covenant.event.v1",
		"event_id":            "event-000001",
		"sequence":            1,
		"run_id":              "run-test",
		"previous_event_hash": strings.Repeat("0", 64),
		"event_hash":          strings.Repeat("a", 64),
		"type":                eventType,
		"status":              "success",
	}
}

func validTaskDocument() map[string]any {
	return map[string]any{
		"id":              "scripted_change",
		"kind":            "scripted",
		"adapter":         "scripted",
		"depends_on":      []any{},
		"obligations":     []any{"obl_requested_file"},
		"timeout_seconds": 30,
		"declared_side_effects": []any{
			map[string]any{"type": "file.write", "resource": "demo-output/report.txt"},
		},
	}
}

func validContractDocument() map[string]any {
	return map[string]any{
		"schema_version": "covenant.contract.v1",
		"objective":      "Create a guarded risky-change demo contract.",
		"workspace": map[string]any{
			"root":   ".",
			"reads":  []any{"examples/risky-change/brief.md"},
			"writes": []any{"demo-output/report.txt"},
		},
		"obligations": []any{
			map[string]any{"id": "obl_requested_file", "text": "The requested file is created.", "required": true},
			map[string]any{"id": "obl_verify_passes", "text": "The verifier passes.", "required": true},
		},
		"tasks": []any{
			map[string]any{
				"id":              "scripted_change",
				"kind":            "scripted",
				"adapter":         "scripted",
				"depends_on":      []any{},
				"obligations":     []any{"obl_requested_file"},
				"timeout_seconds": float64(30),
				"declared_side_effects": []any{
					map[string]any{"type": "file.write", "resource": "demo-output/report.txt"},
				},
			},
			map[string]any{
				"id":              "verify_change",
				"kind":            "verify",
				"adapter":         "scripted",
				"depends_on":      []any{"scripted_change"},
				"obligations":     []any{"obl_verify_passes"},
				"timeout_seconds": float64(30),
			},
		},
		"policy": map[string]any{"mode": "strict"},
		"evaluator": map[string]any{
			"required_obligations": []any{"obl_requested_file", "obl_verify_passes"},
		},
	}
}

func validEvidencePackDocument() map[string]any {
	digest := strings.Repeat("a", 64)
	return map[string]any{
		"schema_version":  "covenant.evidence-pack.v1",
		"run_id":          "demo",
		"contract_digest": digest,
		"ledger_digest":   digest,
		"run_status":      "success",
		"artifact_manifest": []any{
			map[string]any{
				"schema_version":    "covenant.artifact-ref.v1",
				"artifact_id":       "scripted_change-artifact-1",
				"uri":               "covenant-artifact://sha256/" + digest,
				"digest":            digest,
				"media_type":        "text/plain",
				"producer_event_id": "event-000004",
				"path":              "demo-output/report.txt",
			},
		},
		"input_snapshots": []any{
			map[string]any{
				"schema_version": "covenant.input-snapshot.v1",
				"snapshot_id":    "input-000001",
				"source_path":    "examples/risky-change/brief.md",
				"snapshot_path":  "input-snapshots/examples/risky-change/brief.md",
				"digest":         digest,
				"media_type":     "text/markdown",
			},
		},
		"policy_decisions": []any{},
		"failures":         []any{},
		"closure_matrix": map[string]any{
			"schema_version":  "covenant.closure-matrix.v1",
			"run_id":          "demo",
			"contract_digest": digest,
			"status":          "accepted",
			"rows": []any{
				map[string]any{
					"obligation_id":       "obl_requested_file",
					"required":            true,
					"status":              "closed",
					"task_ids":            []any{"scripted_change"},
					"artifact_ids":        []any{"scripted_change-artifact-1"},
					"policy_decision_ids": []any{},
					"reason":              "obligation closed by successful task",
				},
			},
		},
	}
}

func validEvidenceBundleManifestDocument() map[string]any {
	digest := strings.Repeat("b", 64)
	return map[string]any{
		"schema_version":  "covenant.evidence-bundle.v1",
		"run_id":          "bundle-test",
		"contract_digest": digest,
		"ledger_digest":   digest,
		"verification": map[string]any{
			"verified":             true,
			"event_count":          6,
			"artifact_count":       1,
			"input_snapshot_count": 1,
			"failure_count":        0,
		},
		"entries": []any{
			map[string]any{
				"path":       "contract.json",
				"source":     "contract.json",
				"sha256":     digest,
				"size_bytes": 512,
			},
		},
	}
}
