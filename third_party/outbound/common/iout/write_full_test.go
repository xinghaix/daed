package iout

import (
	"errors"
	"io"
	"testing"
)

type scriptedWriter struct {
	writes []int
	i      int
}

func (w *scriptedWriter) Write(p []byte) (int, error) {
	if w.i >= len(w.writes) {
		return 0, nil
	}
	n := w.writes[w.i]
	w.i++
	if n > len(p) {
		n = len(p)
	}
	return n, nil
}

func TestWriteFullLoopsUntilComplete(t *testing.T) {
	w := &scriptedWriter{writes: []int{2, 2}}
	n, err := WriteFull(w, []byte("abcd"))
	if err != nil {
		t.Fatalf("WriteFull: %v", err)
	}
	if n != 4 {
		t.Fatalf("n = %d, want 4", n)
	}
}

func TestWriteFullRejectsZeroProgress(t *testing.T) {
	w := &scriptedWriter{writes: []int{1, 0}}
	n, err := WriteFull(w, []byte("abcd"))
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("err = %v, want ErrShortWrite", err)
	}
	if n != 1 {
		t.Fatalf("n = %d, want 1", n)
	}
}
