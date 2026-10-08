package common

import "sync/atomic"

// LastStringValue keeps the most recently parsed value for an exact string key.
// It is intended for per-connection hot paths where the target usually stays fixed.
type LastStringValue[T any] struct {
	entry atomic.Pointer[lastStringValueEntry[T]]
}

type lastStringValueEntry[T any] struct {
	key   string
	value T
}

// Load returns the cached value when the key matches the latest stored string.
func (c *LastStringValue[T]) Load(key string) (T, bool) {
	entry := c.entry.Load()
	if entry != nil && entry.key == key {
		return entry.value, true
	}
	var zero T
	return zero, false
}

// Store replaces the cached entry with the provided key and value.
func (c *LastStringValue[T]) Store(key string, value T) {
	c.entry.Store(&lastStringValueEntry[T]{
		key:   key,
		value: value,
	})
}
