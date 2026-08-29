#include <cstdint>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>

int SafeFrameCount(int64_t seq_length, int64_t batch_size);
std::size_t rnn_buffer_bytes(int64_t seq_length, int64_t batch_size, int64_t hidden_size);
int rnn_last_offset(int64_t seq_length, int stride);

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        std::cout << "ret=-1\n";
        return 2;
    }

    std::ifstream input(argv[1]);
    int64_t seq_length = 0;
    int64_t batch_size = 0;
    int64_t hidden_size = 0;
    int stride = 0;
    if (!(input >> seq_length >> batch_size >> hidden_size >> stride))
    {
        std::cout << "ret=-1\n";
        return 0;
    }

    const int frames = SafeFrameCount(seq_length, batch_size);
    const std::size_t bytes = rnn_buffer_bytes(seq_length, batch_size, hidden_size);
    const int offset = rnn_last_offset(seq_length, stride);
    const bool rejected = frames < 0 || bytes == 0 || offset < 0;
    std::cout << "ret=" << (rejected ? -1 : 0) << "\n";
    return 0;
}
