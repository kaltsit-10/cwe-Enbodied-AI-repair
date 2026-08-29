#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>

int normalize_cumsum_axis(std::size_t rank, std::int64_t dim, std::size_t* normalized);

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        std::cout << "ret=-1\n";
        return 2;
    }
    std::ifstream input(argv[1]);
    unsigned long long rank = 0;
    long long dim = 0;
    if (!(input >> rank >> dim))
    {
        std::cout << "ret=-1\n";
        return 0;
    }
    std::size_t normalized = 0;
    const int ret = normalize_cumsum_axis(static_cast<std::size_t>(rank), static_cast<std::int64_t>(dim), &normalized);
    std::cout << "ret=" << ret << " normalized=" << normalized << "\n";
    return 0;
}
