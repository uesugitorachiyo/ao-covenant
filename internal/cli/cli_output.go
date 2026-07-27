package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

func writeSchemaValidationJSON(stdout io.Writer, outPath string, report any) error {
	bytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	if err := schema.ValidateBytes(schema.SchemaValidationReportSchemaID, bytes); err != nil {
		return err
	}
	return writeSchemaValidationOutput(stdout, outPath, bytes)
}

func writeSchemaValidationOutput(stdout io.Writer, outPath string, bytes []byte) error {
	bytes = append(bytes, '\n')
	return writeNamedOutputFile(stdout, "schema validate", "schema_validation_report", outPath, bytes)
}

type outputFileSnapshot struct {
	Exists bool
	Bytes  []byte
	Mode   os.FileMode
}

type rollbackOutputFileFunc func(string, outputFileSnapshot) error

var rollbackOutputFileForWrite rollbackOutputFileFunc = rollbackOutputFile

func replaceRollbackOutputFileForWrite(rollback rollbackOutputFileFunc) rollbackOutputFileFunc {
	previous := rollbackOutputFileForWrite
	rollbackOutputFileForWrite = rollback
	return previous
}

const (
	outputPairStageMain    = "main"
	outputPairStageSidecar = "sidecar"
)

type outputPairError struct {
	stage string
	err   error
}

func (err outputPairError) Error() string {
	return err.err.Error()
}

func (err outputPairError) Unwrap() error {
	return err.err
}

func outputPairErrorStage(err error) string {
	var staged outputPairError
	if errors.As(err, &staged) {
		return staged.stage
	}
	return outputPairStageMain
}

func writeNamedOutputFile(stdout io.Writer, commandName string, markerName string, outPath string, bytes []byte) error {
	if strings.TrimSpace(outPath) == "" {
		_, err := stdout.Write(bytes)
		return err
	}
	if err := writeOutputFileBytes(commandName, outPath, bytes); err != nil {
		return err
	}
	_, err := fmt.Fprintf(stdout, "%s=%s\n", markerName, outPath)
	return err
}

func writeOutputFileBytes(commandName string, outPath string, bytes []byte) error {
	if err := validateOutputFileTarget(commandName, outPath); err != nil {
		return err
	}
	if err := os.WriteFile(outPath, bytes, 0o644); err != nil {
		return fmt.Errorf("%s --out write failed: %w", commandName, err)
	}
	return nil
}

func validateOutputFileTarget(commandName string, outPath string) error {
	if strings.TrimSpace(outPath) == "" {
		return fmt.Errorf("%s --out is required", commandName)
	}
	parentDir := filepath.Dir(outPath)
	if info, err := os.Stat(parentDir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s --out parent directory does not exist: %s", commandName, parentDir)
		}
		if strings.Contains(err.Error(), "not a directory") {
			return fmt.Errorf("%s --out parent path is not a directory: %s", commandName, parentDir)
		}
		return fmt.Errorf("%s --out parent path cannot be inspected: %w", commandName, err)
	} else if !info.IsDir() {
		return fmt.Errorf("%s --out parent path is not a directory: %s", commandName, parentDir)
	}
	if info, err := os.Stat(outPath); err == nil {
		if info.IsDir() {
			return fmt.Errorf("%s --out points to a directory: %s", commandName, outPath)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s --out path cannot be inspected: %w", commandName, err)
	}
	return nil
}

// Internal code calls this an output pair. User-facing diagnostics and README text call the second artifact a digest sidecar.
// writeOutputPairWithRollback writes a primary artifact and sidecar as one output pair.
func writeOutputPairWithRollback(commandName string, outPath string, bytes []byte, sidecarPath string, sidecarBytes []byte) error {
	if err := validateOutputFileTarget(commandName, outPath); err != nil {
		return outputPairError{stage: outputPairStageMain, err: err}
	}
	outputSnapshot, err := snapshotOutputFile(outPath)
	if err != nil {
		return outputPairError{stage: outputPairStageMain, err: err}
	}
	if err := writeOutputFileBytes(commandName, outPath, bytes); err != nil {
		return outputPairError{stage: outputPairStageMain, err: err}
	}
	if err := writeOutputFileBytes(commandName, sidecarPath, sidecarBytes); err != nil {
		if rollbackErr := rollbackOutputFileForWrite(outPath, outputSnapshot); rollbackErr != nil {
			err = fmt.Errorf("%w; rollback output: %v", err, rollbackErr)
		}
		return outputPairError{stage: outputPairStageSidecar, err: err}
	}
	return nil
}

func snapshotOutputFile(path string) (outputFileSnapshot, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return outputFileSnapshot{}, nil
		}
		return outputFileSnapshot{}, fmt.Errorf("snapshot output: %w", err)
	}
	if info.IsDir() {
		return outputFileSnapshot{Exists: true, Mode: info.Mode().Perm()}, nil
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		return outputFileSnapshot{}, fmt.Errorf("snapshot output: %w", err)
	}
	return outputFileSnapshot{Exists: true, Bytes: bytes, Mode: info.Mode().Perm()}, nil
}

func rollbackOutputFile(path string, snapshot outputFileSnapshot) error {
	if snapshot.Exists {
		if err := os.WriteFile(path, snapshot.Bytes, snapshot.Mode); err != nil {
			return fmt.Errorf("restore output: %w", err)
		}
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove output: %w", err)
	}
	return nil
}
