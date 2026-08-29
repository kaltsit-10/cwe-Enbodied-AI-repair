#include <cstddef>
#include <cstdint>
#include <limits>

int checked_buffer_offset(std::size_t index_size, std::size_t one_exp_len, std::size_t input_size)
{
    if (one_exp_len > 0 && index_size > std::numeric_limits<std::size_t>::max() / one_exp_len)
        return -1;
    const std::size_t offset = index_size * one_exp_len;
    if (offset >= input_size)
        return -1;
    return 0;
}

int checked_value_product(std::size_t value_size, std::size_t dim)
{
    if (dim > 0 && value_size > std::numeric_limits<std::size_t>::max() / dim)
        return -1;
    (void)(value_size * dim);
    return 0;
}
