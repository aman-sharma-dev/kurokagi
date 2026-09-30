package strictjson

import "testing"

func TestRejectDuplicateKeysIncludingNestedObjects(t *testing.T) {
	for _, raw := range []string{`{"a":1,"a":2}`, `{"a":[{"b":1,"b":2}]}`} {
		if err := RejectDuplicateKeys([]byte(raw)); err == nil {
			t.Fatalf("accepted duplicate member: %s", raw)
		}
	}
	if err := RejectDuplicateKeys([]byte(`{"a":[{"b":1},{"b":2}]}`)); err != nil {
		t.Fatalf("rejected distinct nested members: %v", err)
	}
}

func FuzzRejectDuplicateKeysNeverPanics(f *testing.F) {
	f.Add([]byte(`{"x":1}`))
	f.Add([]byte(`{"x":1,"x":2}`))
	f.Add([]byte(`[{"broken":]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		_ = RejectDuplicateKeys(data)
	})
}
