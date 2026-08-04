package telemetry

import "testing"

func TestEmissionMatrixHasOneClosedOwnerPerCase(t *testing.T) {
	if len(MatrixCases) != 33 || len(SilenceCases) != 12 || len(ReloadCases) != 7 || len(LifecycleCases) != 9 {
		t.Fatalf("generated case counts are incomplete")
	}
	seen := map[string]bool{}
	for _, row := range MatrixCases {
		if row.ID == "" || row.PrimaryEmitter == "" || seen[row.ID] {
			t.Fatalf("invalid matrix row %+v", row)
		}
		seen[row.ID] = true
	}
}
