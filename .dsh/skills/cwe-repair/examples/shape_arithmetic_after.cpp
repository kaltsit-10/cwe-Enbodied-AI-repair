#include <cstdint>
#include <limits>

int compute_offset(int64_t seq_length, int64_t batch_size, int stride, int* output)
{
    if (seq_length < 0 || batch_size < 0 || stride < 0)
        return -1;
    if (seq_length == 0 || batch_size == 0)
        return 0;
    if (batch_size > std::numeric_limits<int64_t>::max() / seq_length)
        return -1;
    const int64_t total64 = seq_length * batch_size;
    if (total64 > std::numeric_limits<int>::max())
        return -1;
    if (seq_length - 1 > std::numeric_limits<int>::max() / stride)
        return -1;
    const int total = static_cast<int>(total64);
    const int offset = static_cast<int>((seq_length - 1) * stride);
    output[offset] = total;
    return total;
}
