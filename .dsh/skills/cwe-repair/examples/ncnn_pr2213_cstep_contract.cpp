#include "layer/packing.h"
#include <cstdio>
#include <limits>

int main()
{
    ncnn::ParamDict pd;
    pd.set(0, 1); // out_elempack

    ncnn::Packing packing;
    if (packing.load_param(pd) != 0)
        return 2;

    // Shape-only external Mat: no allocation and no element loop are needed.
    // The dimensions exercise the int-domain multiplication fixed by PR #2213.
    ncnn::Mat input(std::numeric_limits<int>::max(), (void*)0, 4u, 2);
    ncnn::Mat output;
    ncnn::Option opt;
    opt.use_vulkan_compute = false;
    opt.num_threads = 1;
    if (packing.forward(input, output, opt) != 0)
        return 3;

    const size_t expected = (size_t)std::numeric_limits<int>::max() * 2u;
    if (output.cstep != expected)
    {
        std::fprintf(stderr, "cstep=%zu expected=%zu\n", output.cstep, expected);
        return 1;
    }

    std::puts("cstep_contract=PASS");
    return 0;
}
