// Reduced contract fixture derived from ORT PR #28003 rnn.cc.
// This is not a substitute for the full upstream source checkout.
#include <cstddef>
#include <cstdint>

int rnn_frame_count(int64_t seq_length, int64_t batch_size)
{
    return static_cast<int>(seq_length * batch_size);
}

std::size_t rnn_buffer_bytes(int64_t seq_length, int64_t batch_size, int64_t hidden_size)
{
    return sizeof(float) * seq_length * batch_size * hidden_size;
}

int rnn_last_offset(int64_t seq_length, int stride)
{
    return static_cast<int>((seq_length - 1) * stride);
}
