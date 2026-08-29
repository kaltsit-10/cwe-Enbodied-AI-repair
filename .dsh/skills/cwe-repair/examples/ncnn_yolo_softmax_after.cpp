// Reduced local fixture derived from PR-YoloDetectionOutput-softmax初始化修复.patch.
class YoloDetectionOutput {
public:
    YoloDetectionOutput()
    {
        one_blob_only = false;
        support_inplace = true;
        softmax = 0;
    }

    void destroy_pipeline()
    {
        if (softmax)
            delete softmax;
    }

private:
    Layer* softmax;
    bool one_blob_only;
    bool support_inplace;
};
