//go:build !cuda

package cuda

import (
	"log"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// CalculateAnonSetHardware is a CPU fallback when compiled without the 'cuda' build tag.
// On macOS or environments without Nvidia GPUs, this will be safely loaded instead of the C++ CGO kernel.
func CalculateAnonSetHardware(tx models.Transaction) int {
	log.Println("[WARNING] Hardware acceleration requested, but engine was compiled without CUDA support. Falling back to CPU Heuristics.")
	return 0 // Fallback handled by the CPU SSMP module
}
