#include "net.h"
#include <cstdio>

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        std::fprintf(stderr, "usage: %s <param>\n", argv[0]);
        return 2;
    }

    ncnn::Net net;
    net.opt.num_threads = 1;
    net.opt.use_vulkan_compute = true;
    const int ret = net.load_param(argv[1]);
    std::fprintf(stderr, "load_param ret=%d\n", ret);
    return ret == 0 ? 0 : 1;
}
