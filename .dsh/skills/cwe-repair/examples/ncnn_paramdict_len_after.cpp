// Reduced local fixture derived from PR-paramdict数组len校验修复.patch.
int load_array(int id, int len)
{
    if (id < 0 || id >= NCNN_MAX_PARAM_COUNT)
        return -1;

    if (len <= 0)
        return -1;

    d->params[id].v.create(len);

    if (d->params[id].v.empty())
        return -1;

    float* ptr = d->params[id].v;
    nread = dr.read(ptr, sizeof(float) * len);
    if (nread != sizeof(float) * len)
        return -1;

    return 0;
}
