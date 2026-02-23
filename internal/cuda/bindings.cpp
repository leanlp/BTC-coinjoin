//go:build cuda

#include "bindings.h"
#include <iostream>

// Forward declaration of the CUDA launcher defined in kernel.cu
int launch_cuda_ssmp(long long* inputs, int num_inputs, long long* outputs, int num_outputs);

extern "C" {

int CalculateAnonSetCUDA(long long* inputs, int num_inputs, long long* outputs, int num_outputs) {
    // This is the bridge block where Go calls C++, and C++ calls the GPU kernel
    try {
        return launch_cuda_ssmp(inputs, num_inputs, outputs, num_outputs);
    } catch (...) {
        // Fallback or error state if CUDA execution fails
        return -1;
    }
}

}
