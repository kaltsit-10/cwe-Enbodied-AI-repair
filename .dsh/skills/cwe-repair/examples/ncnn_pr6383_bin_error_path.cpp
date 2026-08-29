#include "net.h"
#include <cstdio>

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        std::fprintf(stderr, "usage: %s <param.bin>\n", argv[0]);
        return 2;
    }

    ncnn::Net net;
    net.opt.num_threads = 1;
    const int ret = net.load_param_bin(argv[1]);
    std::fprintf(stderr, "load_param_bin ret=%d\n", ret);
    return ret == 0 ? 0 : 1;
}
