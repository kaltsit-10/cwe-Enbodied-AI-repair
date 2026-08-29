#include <cstdint>

int compute_offset(int64_t seq_length, int64_t batch_size, int stride, int* output)
{
    int total = static_cast<int>(seq_length * batch_size);
    int offset = (seq_length - 1) * stride;
    output[offset] = total;
    return total;
}
