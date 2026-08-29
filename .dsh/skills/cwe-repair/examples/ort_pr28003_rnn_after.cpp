// Reduced contract fixture derived from ORT PR #28003 rnn.cc.
// This is not a substitute for the full upstream source checkout.
#include <cstddef>
#include <cstdint>
#include <limits>

std::size_t SafeMulSize(std::size_t a, std::size_t b, std::size_t c, std::size_t d)
{
    if (a != 0 && b > std::numeric_limits<std::size_t>::max() / a)
        return 0;
    const std::size_t ab = a * b;
    if (c != 0 && ab > std::numeric_limits<std::size_t>::max() / c)
        return 0;
    const std::size_t abc = ab * c;
    if (d != 0 && abc > std::numeric_limits<std::size_t>::max() / d)
        return 0;
    return abc * d;
}

int SafeFrameCount(int64_t seq_length, int64_t batch_size)
{
    if (seq_length < 0 || batch_size < 0 ||
        batch_size > std::numeric_limits<int>::max() / (seq_length == 0 ? 1 : seq_length))
        return -1;
    return static_cast<int>(seq_length * batch_size);
}

std::size_t rnn_buffer_bytes(int64_t seq_length, int64_t batch_size, int64_t hidden_size)
{
    if (seq_length < 0 || batch_size < 0 || hidden_size < 0)
        return 0;
    return SafeMulSize(sizeof(float), static_cast<std::size_t>(seq_length),
                       static_cast<std::size_t>(batch_size), static_cast<std::size_t>(hidden_size));
}

int rnn_last_offset(int64_t seq_length, int stride)
{
    if (seq_length <= 0 || stride < 0 ||
        seq_length - 1 > std::numeric_limits<int>::max() / (stride == 0 ? 1 : stride))
        return -1;
    return static_cast<int>((seq_length - 1) * stride);
}
