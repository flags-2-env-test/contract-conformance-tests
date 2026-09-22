package reactive_maps

import "testing"

func TestPrecedenceRevealAndShadowedMutation(t *testing.T) {
	m := New()
	m.ReplaceStringLayer("env", "env", 100, map[string]string{"PORT": "3000", "ORES_PUBLIC_ORIGIN": "https://example.test"})
	m.ReplaceStringLayer("flags", "flags", 200, map[string]string{"PORT": "8080"})
	if value, _ := m.GetVal("PORT"); value != "8080" {
		t.Fatalf("expected 8080, got %q", value)
	}
	entry, ok := m.GetEntry("PORT")
	if !ok || entry.Source != "flags" || entry.Layer != "flags" || entry.IsPublic {
		t.Fatalf("unexpected entry: %#v", entry)
	}
	if public := m.GetPublicEntries(); public["ORES_PUBLIC_ORIGIN"].Value != "https://example.test" {
		t.Fatalf("public entry missing")
	}

	var events []ChangeEvent
	m.Subscribe(func(event ChangeEvent) { events = append(events, event) })
	before := m.Revision()
	m.PatchStringLayer("env", "env", 100, map[string]string{"PORT": "3001"})
	if m.Revision() != before || len(events) != 0 {
		t.Fatalf("shadowed mutation emitted")
	}
	if !m.RemoveFromLayer("flags", "PORT") {
		t.Fatalf("remove failed")
	}
	if value, _ := m.GetVal("PORT"); value != "3001" {
		t.Fatalf("expected reveal 3001, got %q", value)
	}
	if len(events) != 1 || events[0].Revision != before+1 {
		t.Fatalf("unexpected events: %#v", events)
	}
}

func TestPublicPrefixAndRuntimeOverride(t *testing.T) {
	m := New()
	m.ReplaceStringLayer("env", "env", 100, map[string]string{"CLIENT_KEY": "x"})
	count := 0
	m.Subscribe(func(ChangeEvent) { count++ })
	m.SetPublicPrefix("CLIENT_")
	entry, _ := m.GetEntry("CLIENT_KEY")
	if !entry.IsPublic || count != 1 {
		t.Fatalf("prefix update not reactive: %#v count=%d", entry, count)
	}
	f := false
	m.SetVal("CLIENT_KEY", "runtime", &f)
	entry, _ = m.GetEntry("CLIENT_KEY")
	if entry.Value != "runtime" || entry.Source != "runtime" || entry.Layer != RuntimeLayer || entry.IsPublic {
		t.Fatalf("bad runtime entry: %#v", entry)
	}
}

func TestCallbacksRunOutsideLock(t *testing.T) {
	m := New()
	m.ReplaceStringLayer("env", "env", 100, map[string]string{"K": "a"})
	called := false
	m.Subscribe(func(ChangeEvent) {
		called = true
		if _, ok := m.GetVal("K"); !ok {
			t.Fatalf("callback could not read map")
		}
	})
	m.PatchStringLayer("env", "env", 100, map[string]string{"K": "b"})
	if !called {
		t.Fatalf("subscriber was not called")
	}
}
