package reactive_maps

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

const (
	DefaultPublicPrefix = "ORES_PUBLIC_"
	RuntimeLayer        = "__runtime"
	RuntimePriority     = 1_000_000
)

type EntryInput struct {
	Value     string
	Public    bool
	HasPublic bool
}

type ResolvedEntry struct {
	Value    string
	Source   string
	IsPublic bool
	Layer    string
}

type ChangeEvent struct {
	Key      string
	OldEntry *ResolvedEntry
	NewEntry *ResolvedEntry
	Revision uint64
}

type LayerInfo struct {
	Name     string
	Source   string
	Priority int
	Order    uint64
	Size     int
}

type Subscriber func(ChangeEvent)

type rawEntry struct {
	value          string
	publicOverride *bool
}

type layer struct {
	name     string
	source   string
	priority int
	order    uint64
	entries  map[string]rawEntry
}

type ReactiveMap struct {
	mu               sync.RWMutex
	layers           map[string]*layer
	publicPrefix     string
	revision         uint64
	nextLayerOrder   uint64
	nextSubscription uint64
	subscribers      map[uint64]Subscriber
}

func New() *ReactiveMap {
	return NewWithPublicPrefix(DefaultPublicPrefix)
}

func NewWithPublicPrefix(prefix string) *ReactiveMap {
	return &ReactiveMap{
		layers:           make(map[string]*layer),
		publicPrefix:     prefix,
		nextSubscription: 1,
		subscribers:      make(map[uint64]Subscriber),
	}
}

func (m *ReactiveMap) Revision() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.revision
}

func (m *ReactiveMap) PublicPrefix() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.publicPrefix
}

func (m *ReactiveMap) GetVal(key string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entry, ok := m.resolveLocked(key)
	if !ok {
		return "", false
	}
	return entry.Value, true
}

func (m *ReactiveMap) GetEntry(key string) (ResolvedEntry, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.resolveLocked(key)
}

func (m *ReactiveMap) GetAllEntries() map[string]ResolvedEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.snapshotLocked()
}

func (m *ReactiveMap) GetPublicEntries() map[string]ResolvedEntry {
	return m.filteredEntries(true)
}

func (m *ReactiveMap) GetPrivateEntries() map[string]ResolvedEntry {
	return m.filteredEntries(false)
}

func (m *ReactiveMap) SetVal(key, value string, isPublic *bool) {
	m.mutate(func() {
		l := m.ensureLayerLocked(RuntimeLayer, "runtime", RuntimePriority)
		l.entries[key] = rawEntry{value: value, publicOverride: cloneBool(isPublic)}
	})
}

func (m *ReactiveMap) SetValInLayer(layerName, key, value string, isPublic *bool) error {
	var err error
	m.mutate(func() {
		l, ok := m.layers[layerName]
		if !ok {
			err = fmt.Errorf("unknown layer: %s", layerName)
			return
		}
		l.entries[key] = rawEntry{value: value, publicOverride: cloneBool(isPublic)}
	})
	return err
}

func (m *ReactiveMap) ReplaceLayer(name, source string, priority int, values map[string]EntryInput) {
	m.mutate(func() {
		order := m.nextLayerOrder
		if existing, ok := m.layers[name]; ok {
			order = existing.order
		} else {
			m.nextLayerOrder++
		}
		entries := make(map[string]rawEntry, len(values))
		for key, input := range values {
			entries[key] = input.toRaw()
		}
		m.layers[name] = &layer{name: name, source: source, priority: priority, order: order, entries: entries}
	})
}

func (m *ReactiveMap) ReplaceStringLayer(name, source string, priority int, values map[string]string) {
	inputs := make(map[string]EntryInput, len(values))
	for key, value := range values {
		inputs[key] = EntryInput{Value: value}
	}
	m.ReplaceLayer(name, source, priority, inputs)
}

func (m *ReactiveMap) PatchLayer(name, source string, priority int, values map[string]EntryInput) {
	m.mutate(func() {
		l, ok := m.layers[name]
		if !ok {
			l = &layer{name: name, source: source, priority: priority, order: m.nextLayerOrder, entries: make(map[string]rawEntry)}
			m.nextLayerOrder++
			m.layers[name] = l
		} else {
			l.source = source
			l.priority = priority
		}
		for key, input := range values {
			l.entries[key] = input.toRaw()
		}
	})
}

func (m *ReactiveMap) PatchStringLayer(name, source string, priority int, values map[string]string) {
	inputs := make(map[string]EntryInput, len(values))
	for key, value := range values {
		inputs[key] = EntryInput{Value: value}
	}
	m.PatchLayer(name, source, priority, inputs)
}

func (m *ReactiveMap) RemoveFromLayer(layerName, key string) bool {
	removed := false
	m.mutate(func() {
		l, ok := m.layers[layerName]
		if !ok {
			return
		}
		if _, ok := l.entries[key]; !ok {
			return
		}
		delete(l.entries, key)
		removed = true
	})
	return removed
}

func (m *ReactiveMap) RemoveLayer(layerName string) bool {
	removed := false
	m.mutate(func() {
		if _, ok := m.layers[layerName]; !ok {
			return
		}
		delete(m.layers, layerName)
		removed = true
	})
	return removed
}

func (m *ReactiveMap) SetLayerPriority(layerName string, priority int) error {
	var err error
	m.mutate(func() {
		l, ok := m.layers[layerName]
		if !ok {
			err = fmt.Errorf("unknown layer: %s", layerName)
			return
		}
		l.priority = priority
	})
	return err
}

func (m *ReactiveMap) SetPublicPrefix(prefix string) {
	m.mu.RLock()
	same := m.publicPrefix == prefix
	m.mu.RUnlock()
	if same {
		return
	}
	m.mutate(func() { m.publicPrefix = prefix })
}

func (m *ReactiveMap) GetLayerOrder() []LayerInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]LayerInfo, 0, len(m.layers))
	for _, l := range m.layers {
		out = append(out, LayerInfo{Name: l.name, Source: l.source, Priority: l.priority, Order: l.order, Size: len(l.entries)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].Order < out[j].Order
	})
	return out
}

func (m *ReactiveMap) Subscribe(subscriber Subscriber) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.nextSubscription
	m.nextSubscription++
	m.subscribers[id] = subscriber
	return id
}

func (m *ReactiveMap) Unsubscribe(id uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.subscribers[id]; !ok {
		return false
	}
	delete(m.subscribers, id)
	return true
}

func (input EntryInput) toRaw() rawEntry {
	if !input.HasPublic {
		return rawEntry{value: input.Value}
	}
	v := input.Public
	return rawEntry{value: input.Value, publicOverride: &v}
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	v := *value
	return &v
}

func cloneResolvedPtr(value *ResolvedEntry) *ResolvedEntry {
	if value == nil {
		return nil
	}
	v := *value
	return &v
}

func sameEntry(a *ResolvedEntry, b *ResolvedEntry) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func (m *ReactiveMap) ensureLayerLocked(name, source string, priority int) *layer {
	if l, ok := m.layers[name]; ok {
		return l
	}
	l := &layer{name: name, source: source, priority: priority, order: m.nextLayerOrder, entries: make(map[string]rawEntry)}
	m.nextLayerOrder++
	m.layers[name] = l
	return l
}

func (m *ReactiveMap) resolveLocked(key string) (ResolvedEntry, bool) {
	var winner *layer
	var raw rawEntry
	found := false
	for _, l := range m.layers {
		candidate, ok := l.entries[key]
		if !ok {
			continue
		}
		if !found || l.priority > winner.priority || (l.priority == winner.priority && l.order > winner.order) {
			winner = l
			raw = candidate
			found = true
		}
	}
	if !found {
		return ResolvedEntry{}, false
	}
	isPublic := strings.HasPrefix(key, m.publicPrefix)
	if raw.publicOverride != nil {
		isPublic = *raw.publicOverride
	}
	return ResolvedEntry{Value: raw.value, Source: winner.source, IsPublic: isPublic, Layer: winner.name}, true
}

func (m *ReactiveMap) snapshotLocked() map[string]ResolvedEntry {
	keys := make(map[string]struct{})
	for _, l := range m.layers {
		for key := range l.entries {
			keys[key] = struct{}{}
		}
	}
	out := make(map[string]ResolvedEntry, len(keys))
	for key := range keys {
		if entry, ok := m.resolveLocked(key); ok {
			out[key] = entry
		}
	}
	return out
}

func (m *ReactiveMap) filteredEntries(public bool) map[string]ResolvedEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]ResolvedEntry)
	for key, entry := range m.snapshotLocked() {
		if entry.IsPublic == public {
			out[key] = entry
		}
	}
	return out
}

func (m *ReactiveMap) mutate(change func()) {
	m.mu.Lock()
	before := m.snapshotLocked()
	change()
	after := m.snapshotLocked()
	keys := make(map[string]struct{}, len(before)+len(after))
	for key := range before {
		keys[key] = struct{}{}
	}
	for key := range after {
		keys[key] = struct{}{}
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)

	changed := make([]string, 0)
	for _, key := range ordered {
		beforeEntry, beforeOK := before[key]
		afterEntry, afterOK := after[key]
		var a, b *ResolvedEntry
		if beforeOK {
			v := beforeEntry
			a = &v
		}
		if afterOK {
			v := afterEntry
			b = &v
		}
		if !sameEntry(a, b) {
			changed = append(changed, key)
		}
	}
	if len(changed) == 0 {
		m.mu.Unlock()
		return
	}

	m.revision++
	revision := m.revision
	subscribers := make([]Subscriber, 0, len(m.subscribers))
	for _, subscriber := range m.subscribers {
		subscribers = append(subscribers, subscriber)
	}
	events := make([]ChangeEvent, 0, len(changed))
	for _, key := range changed {
		var oldPtr, newPtr *ResolvedEntry
		if oldEntry, ok := before[key]; ok {
			oldPtr = cloneResolvedPtr(&oldEntry)
		}
		if newEntry, ok := after[key]; ok {
			newPtr = cloneResolvedPtr(&newEntry)
		}
		events = append(events, ChangeEvent{Key: key, OldEntry: oldPtr, NewEntry: newPtr, Revision: revision})
	}
	m.mu.Unlock()

	for _, event := range events {
		for _, subscriber := range subscribers {
			subscriber(event)
		}
	}
}
