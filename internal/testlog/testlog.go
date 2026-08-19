// Package testlog implements an in-memory transparency log for tests.
package testlog

import (
	"fmt"
	"io"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// Log is a signed-note transparency log with an in-memory Merkle tree.
type Log struct {
	Origin string
	Signer note.Signer
	VKey   string

	hashes []tlog.Hash
	n      int64
}

// New returns an empty Log with a new signed-note keypair.
func New(rand io.Reader, origin string) (*Log, error) {
	skey, vkey, err := note.GenerateKey(rand, origin)
	if err != nil {
		return nil, err
	}

	signer, err := note.NewSigner(skey)
	if err != nil {
		return nil, err
	}

	return &Log{Origin: origin, Signer: signer, VKey: vkey}, nil
}

// Size returns the current tree size.
func (l *Log) Size() int64 { return l.n }

// ReadHashes implements tlog.HashReader.
func (l *Log) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, x := range indexes {
		if x < 0 || x >= int64(len(l.hashes)) {
			return nil, fmt.Errorf("hash index %d out of range", x)
		}
		out[i] = l.hashes[x]
	}
	return out, nil
}

// Append records new entries in the log.
func (l *Log) Append(records ...string) error {
	for _, rec := range records {
		hs, err := tlog.StoredHashes(l.n, []byte(rec), l)
		if err != nil {
			return err
		}
		l.hashes = append(l.hashes, hs...)
		l.n++
	}
	return nil
}

// TreeHash returns the Merkle root at the given tree size.
func (l *Log) TreeHash(size int64) (tlog.Hash, error) {
	return tlog.TreeHash(size, l)
}

// Checkpoint returns a signed checkpoint note at the current tree size,
// alongside the parsed torchwood.Checkpoint.
func (l *Log) Checkpoint() ([]byte, torchwood.Checkpoint, error) {
	th, err := l.TreeHash(l.n)
	if err != nil {
		return nil, torchwood.Checkpoint{}, err
	}
	return l.CheckpointWithHash(l.n, th)
}

// CheckpointWithHash signs a checkpoint for (size, root); useful for
// crafting invalid checkpoints in tests.
func (l *Log) CheckpointWithHash(size int64, root tlog.Hash) ([]byte, torchwood.Checkpoint, error) {
	cp := torchwood.Checkpoint{
		Origin: l.Origin,
		Tree:   tlog.Tree{N: size, Hash: root},
	}
	signed, err := note.Sign(&note.Note{Text: cp.String()}, l.Signer)
	if err != nil {
		return nil, torchwood.Checkpoint{}, err
	}
	return signed, cp, nil
}

// ProveTree returns a consistency proof from older to newer tree size.
func (l *Log) ProveTree(newer, older int64) (tlog.TreeProof, error) {
	return tlog.ProveTree(newer, older, l)
}
