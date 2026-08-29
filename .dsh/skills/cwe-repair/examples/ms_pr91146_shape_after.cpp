#include <cstddef>
#include <cstdint>
#include <vector>

int validate_nonnegative_shape(const std::vector<std::int64_t>& shape)
{
    for (std::size_t i = 0; i < shape.size(); ++i) {
        if (shape[i] < 0)
            return -1;
    }
    return 0;
}
