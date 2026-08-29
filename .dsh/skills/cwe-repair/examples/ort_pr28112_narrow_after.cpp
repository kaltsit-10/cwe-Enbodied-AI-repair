#include <cstddef>
#include <cstdint>
#include <limits>

template <typename T>
T narrow(std::size_t value)
{
    return static_cast<T>(value);
}

int validate_model_data_length(std::size_t model_data_length)
{
    if (model_data_length > static_cast<std::size_t>(std::numeric_limits<int32_t>::max()))
        return -1;
    const int32_t model_data_length_int = narrow<int32_t>(model_data_length);
    (void)model_data_length_int;
    return 0;
}
