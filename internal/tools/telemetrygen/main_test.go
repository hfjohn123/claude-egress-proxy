package main

import "testing"

func TestValidateRejectsCaseMutations(t *testing.T) {
	m, err := readManifest("../../../schema/telemetry.yaml")
	if err != nil {
		t.Fatal(err)
	}
	groups := []struct {
		name string
		rows []emission
	}{
		{"matrix", m.Matrix}, {"silence", m.Silence}, {"reload", m.Reload}, {"lifecycle", m.Lifecycle},
	}
	for _, group := range groups {
		for _, field := range []string{"id", "owner", "required", "forbidden"} {
			t.Run(group.name+"/"+field, func(t *testing.T) {
				copy := m
				rows := append([]emission(nil), group.rows...)
				switch field {
				case "id":
					rows[0].ID += "_mutated"
				case "owner":
					rows[0].PrimaryEmitter += "_mutated"
				case "required":
					rows[0].Required += " mutated"
				case "forbidden":
					rows[0].Forbidden += " mutated"
				}
				switch group.name {
				case "matrix":
					copy.Matrix = rows
				case "silence":
					copy.Silence = rows
				case "reload":
					copy.Reload = rows
				case "lifecycle":
					copy.Lifecycle = rows
				}
				if err := validate(copy); err == nil {
					t.Fatalf("validate accepted %s mutation", field)
				}
			})
		}
		t.Run(group.name+"/reordered", func(t *testing.T) {
			copy := m
			rows := append([]emission(nil), group.rows...)
			rows[0], rows[1] = rows[1], rows[0]
			switch group.name {
			case "matrix":
				copy.Matrix = rows
			case "silence":
				copy.Silence = rows
			case "reload":
				copy.Reload = rows
			case "lifecycle":
				copy.Lifecycle = rows
			}
			if err := validate(copy); err == nil {
				t.Fatal("validate accepted reordered rows")
			}
		})
	}
}
