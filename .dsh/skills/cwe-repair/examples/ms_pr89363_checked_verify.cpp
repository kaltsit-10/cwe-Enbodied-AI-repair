#include <cstddef>
#include <fstream>
#include <iostream>
#include <limits>

int checked_buffer_offset(std::size_t index_size, std::size_t one_exp_len, std::size_t input_size);
int checked_value_product(std::size_t value_size, std::size_t dim);

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        std::cout << "ret=-1\n";
        return 2;
    }
    std::ifstream input(argv[1]);
    unsigned long long index_size = 0;
    unsigned long long one_exp_len = 0;
    unsigned long long input_size = 0;
    unsigned long long value_size = 0;
    unsigned long long dim = 0;
    if (!(input >> index_size >> one_exp_len >> input_size >> value_size >> dim))
    {
        std::cout << "ret=-1\n";
        return 0;
    }
    const int offset_ret = checked_buffer_offset(
        static_cast<std::size_t>(index_size),
        static_cast<std::size_t>(one_exp_len),
        static_cast<std::size_t>(input_size));
    const int product_ret = checked_value_product(
        static_cast<std::size_t>(value_size), static_cast<std::size_t>(dim));
    std::cout << "ret=" << ((offset_ret == 0 && product_ret == 0) ? 0 : -1) << "\n";
    return 0;
}
