#include <cstdint>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>

int validate_model_data_length(std::size_t model_data_length);

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        std::cout << "ret=-1\n";
        return 2;
    }
    std::ifstream input(argv[1]);
    unsigned long long raw = 0;
    if (!(input >> raw))
    {
        std::cout << "ret=-1\n";
        return 0;
    }
    const int ret = validate_model_data_length(static_cast<std::size_t>(raw));
    std::cout << "ret=" << ret << "\n";
    return 0;
}
