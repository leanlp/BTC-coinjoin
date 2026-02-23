#ifndef BINDINGS_H
#define BINDINGS_H

#ifdef __cplusplus
extern "C" {
#endif

// CalculateAnonSetCUDA takes an array of inputs and outputs (in satoshis)
// and returns the calculated AnonSet size by solving the Subset Sum Matching
// Problem on the Nvidia GPU.
int CalculateAnonSetCUDA(long long* inputs, int num_inputs, long long* outputs, int num_outputs);

#ifdef __cplusplus
}
#endif

#endif // BINDINGS_H
