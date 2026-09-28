package blockcount

import "errors"

const reliableWrite = uint32(1 << 31)

var (
	errTooLarge        = errors.New("transfer size cannot exceed 65535 blocks")
	errReliableNonRPMB = errors.New("reliable write flag requires RPMB transfer")
)

// Decode separates the RPMB reliable-write flag from the transfer count.
func Decode(encoded uint32, rpmb bool) (uint32, error) {
	count := encoded & 0xffff
	flags := encoded &^ 0xffff

	if flags == 0 {
		return count, nil
	}
	if flags != reliableWrite {
		return 0, errTooLarge
	}
	if !rpmb {
		return 0, errReliableNonRPMB
	}
	if count == 0 {
		return 0, errTooLarge
	}

	return count, nil
}
