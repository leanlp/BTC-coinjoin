//go:build cuda

package cuda

/*
#cgo LDFLAGS: -L${SRCDIR} -lkernel -L/usr/local/cuda/lib64 -lcudart
#include "bindings.h"
*/
import "C"
import (
	"log"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// CalculateAnonSetHardware accelerates the Anonymity Set calculation
// by offloading the mathematical power set generation to the Nvidia GPU (RTX 3080).
func CalculateAnonSetHardware(tx models.Transaction) int {
	// 1. Convert Go BTC Float slices into primitive C arrays (Satoshis)
	numInputs := len(tx.Inputs)
	numOutputs := len(tx.Outputs)

	if numInputs == 0 || numOutputs == 0 {
		return 0
	}

	cInputs := make([]C.longlong, numInputs)
	cOutputs := make([]C.longlong, numOutputs)

	for i, in := range tx.Inputs {
		cInputs[i] = C.longlong(in.Value)
	}

	for i, out := range tx.Outputs {
		cOutputs[i] = C.longlong(out.Value)
	}

	log.Printf("[CUDA] Offloading %d inputs & %d outputs to GPU VRAM for parallel SSMP calculation...", numInputs, numOutputs)

	// 2. Cross the CGO bridge to invoke the CUDA C++ kernel
	// We pass the raw pointers of the Go slices directly to C.
	anonSet := C.CalculateAnonSetCUDA(
		(*C.longlong)(&cInputs[0]), C.int(numInputs),
		(*C.longlong)(&cOutputs[0]), C.int(numOutputs),
	)

	return int(anonSet)
}
