#include <cstddef>
#include <cstdint>

int normalize_cumsum_axis(std::size_t rank, std::int64_t dim, std::size_t* normalized)
{
    const auto rank_i = static_cast<std::int64_t>(rank);
    if (!(dim >= -rank_i && dim <= rank_i - 1))
        return -1;
    if (dim < 0)
        dim += rank_i;
    *normalized = static_cast<std::size_t>(dim);
    return 0;
}
