package release_test

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	checkoutAction = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
	setupGoAction  = "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e"
	uploadAction   = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
)

type ciWorkflow struct {
	Jobs map[string]ciJob `yaml:"jobs"`
}

type ciJob struct {
	Name           string   `yaml:"name"`
	RunsOn         string   `yaml:"runs-on"`
	TimeoutMinutes int      `yaml:"timeout-minutes"`
	Steps          []ciStep `yaml:"steps"`
}

type ciStep struct {
	Uses string         `yaml:"uses"`
	Run  string         `yaml:"run"`
	If   string         `yaml:"if"`
	With map[string]any `yaml:"with"`
}

func TestCIE2EJobContract(t *testing.T) {
	workflow := loadCIWorkflow(t)
	job, ok := workflow.Jobs["e2e"]
	if !ok {
		t.Fatal("CI has no e2e job")
	}
	if job.Name != "E2E" || job.RunsOn != "ubuntu-latest" || job.TimeoutMinutes != 5 {
		t.Fatalf("E2E job = %+v", job)
	}
	if !job.runs("sudo --preserve-env=PATH bash scripts/verify-e2e.sh") {
		t.Fatal("E2E job does not run the native harness")
	}
	checkout := job.step(checkoutAction)
	setupGo := job.step(setupGoAction)
	upload := job.step(uploadAction)
	if checkout == nil || setupGo == nil || setupGo.With["go-version"] != "1.26.5" || setupGo.With["check-latest"] != true {
		t.Fatal("E2E job does not use the pinned checkout and Go toolchain contract")
	}
	if upload == nil || upload.If != "failure()" || upload.With["name"] != "e2e-failure" || upload.With["path"] != "out/e2e" || upload.With["if-no-files-found"] != "ignore" || upload.With["retention-days"] != 7 {
		t.Fatal("E2E failure artifact contract is incomplete")
	}
}

func loadCIWorkflow(t *testing.T) ciWorkflow {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var workflow ciWorkflow
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatal(err)
	}
	return workflow
}

func (j ciJob) runs(command string) bool {
	for _, step := range j.Steps {
		if step.Run == command {
			return true
		}
	}
	return false
}

func (j ciJob) step(action string) *ciStep {
	for index := range j.Steps {
		if j.Steps[index].Uses == action {
			return &j.Steps[index]
		}
	}
	return nil
}
