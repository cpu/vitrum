//go:build usbarmory

#include "textflag.h"

// func habCallStatus(fn, config, state uintptr) byte
TEXT ·habCallStatus(SB),NOSPLIT,$4-13
	MOVW fn+0(FP), R2
	MOVW config+4(FP), R0
	MOVW state+8(FP), R1
	BL (R2)
	MOVB R0, ret+12(FP)
	RET

// func habCallEvent(fn uintptr, status byte, index uint32, event, size uintptr) byte
TEXT ·habCallEvent(SB),NOSPLIT,$4-21
	MOVW fn+0(FP), R4
	MOVBU status+4(FP), R0
	MOVW index+8(FP), R1
	MOVW event+12(FP), R2
	MOVW size+16(FP), R3
	BL (R4)
	MOVB R0, ret+20(FP)
	RET
