package witness

import (
	"bytes"
	"fmt"

	"golang.org/x/mod/sumdb/tlog"
)

// EncodeAddCheckpoint assembles a c2sp.org/tlog-witness add-checkpoint
// request body: `old N`, zero or more base64 proof lines, a blank
// separator, and the signed checkpoint note.
func EncodeAddCheckpoint(old int64, proof tlog.TreeProof, cpNote []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "old %d\n", old)
	for _, h := range proof {
		fmt.Fprintln(&b, h)
	}
	b.WriteString("\n")
	b.Write(cpNote)
	return b.Bytes()
}
