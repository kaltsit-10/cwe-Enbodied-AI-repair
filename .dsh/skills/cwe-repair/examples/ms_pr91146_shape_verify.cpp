#include <cstdint>
#include <fstream>
#include <iostream>
#include <vector>

int validate_nonnegative_shape(const std::vector<std::int64_t>& shape);

int main(int argc, char** argv)
{
    if (argc != 2) {
        std::cout << "ret=-1\n";
        return 2;
    }
    std::ifstream input(argv[1]);
    std::size_t count = 0;
    if (!(input >> count)) {
        std::cout << "ret=-1\n";
        return 0;
    }
    std::vector<std::int64_t> shape;
    shape.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        std::int64_t value = 0;
        if (!(input >> value)) {
            std::cout << "ret=-1\n";
            return 0;
        }
        shape.push_back(value);
    }
    std::cout << "ret=" << validate_nonnegative_shape(shape) << "\n";
    return 0;
}
