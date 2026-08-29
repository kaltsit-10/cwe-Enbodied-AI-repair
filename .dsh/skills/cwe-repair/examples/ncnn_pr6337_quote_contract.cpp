#include <cstdio>
#include <string>

#include "datareader.h"
#include "paramdict.h"

class ParamDictHarness : public ncnn::ParamDict
{
public:
    int load_text(const char* text)
    {
        const unsigned char* memory = (const unsigned char*)text;
        ncnn::DataReaderFromMemory reader(memory);
        return ncnn::ParamDict::load_param(reader);
    }
};

int main()
{
    // This is the valid adjacent-token form added by Tencent/ncnn PR #6337.
    const char* input = "0=bij,bjk->bik 2=\"X\" 6=\"qwqwqwq\"";
    ParamDictHarness params;
    const int ret = params.load_text(input);
    const std::string first = params.get(0, "");
    const std::string trailing = params.get(6, "");

    if (ret != 0 || first != "bij,bjk->bik" || trailing != "qwqwqwq")
    {
        std::fprintf(stderr, "quote_contract ret=%d first=%s trailing=%s\n", ret, first.c_str(), trailing.c_str());
        return 1;
    }

    std::puts("quote_contract=PASS");
    return 0;
}
