#include <cassert>
#include <cstdint>
#include <limits>

int SafeFrameCount(int64_t seq_length, int64_t batch_size);
std::size_t rnn_buffer_bytes(int64_t seq_length, int64_t batch_size, int64_t hidden_size);
int rnn_last_offset(int64_t seq_length, int stride);

int main()
{
    assert(SafeFrameCount(2, 3) == 6);
    assert(SafeFrameCount(-1, 2) == -1);
    assert(SafeFrameCount(std::numeric_limits<int64_t>::max(), 2) == -1);

    assert(rnn_buffer_bytes(2, 3, 4) == 96);
    assert(rnn_buffer_bytes(-1, 3, 4) == 0);

    assert(rnn_last_offset(3, 4) == 8);
    assert(rnn_last_offset(0, 4) == -1);
    assert(rnn_last_offset(std::numeric_limits<int64_t>::max(), 4) == -1);
    return 0;
}
