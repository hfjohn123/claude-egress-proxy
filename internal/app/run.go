package app

import (
	"bytes"
	"context"
	"io"
	"runtime"

	"github.com/hfjohn123/claude-egress-proxy/internal/cli"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
)

// Run parses args, invokes one selected handler, and writes its fixed output.
func Run(ctx context.Context, deps Dependencies, args []string, stdout, stderr io.Writer) int {
	invocation, usage := cli.Parse(args, runtime.GOOS)
	if usage != nil {
		writeComplete(stderr, usage.Bytes)
		return 2
	}
	handler := deps.handler(invocation.Command)
	if handler == nil {
		return 1
	}
	result := handler(ctx, invocation)
	if result.ExitCode < 0 || result.ExitCode > 2 {
		panic("invalid handler exit code")
	}
	if !writeComplete(stdout, result.Stdout) {
		if len(result.OutputFailed) != 0 {
			writeComplete(stderr, result.OutputFailed)
		}
		return 1
	}
	writeComplete(stderr, result.Stderr)
	return result.ExitCode
}

// RunService preserves a fatal diagnostic as its SCM service-specific code.
func RunService(ctx context.Context, deps Dependencies, args []string) (bool, uint32) {
	var stderr bytes.Buffer
	exit := Run(ctx, deps, args, io.Discard, &stderr)
	for code := contract.D001; code <= contract.D011; code++ {
		if bytes.Equal(stderr.Bytes(), contract.Fatal(code)) {
			return true, contract.ServiceCode(code)
		}
	}
	return false, uint32(exit)
}

func writeComplete(writer io.Writer, bytes []byte) bool {
	if len(bytes) == 0 {
		return true
	}
	n, err := writer.Write(bytes)
	return err == nil && n == len(bytes)
}
