#include <cstddef>
#include <cstdint>
#include <limits>

int load_model(const std::size_t model_data_length)
{
    if (model_data_length > static_cast<std::size_t>(std::numeric_limits<int32_t>::max()))
        return -1;
    return narrow<int32_t>(model_data_length);
}
