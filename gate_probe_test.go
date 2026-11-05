package minimalcsp_test

import "testing"

// This failing test proves the merge gate blocks a red build. It must never merge.
func TestGateProbe(t *testing.T) {
	t.Fatal("deliberate failure")
}
