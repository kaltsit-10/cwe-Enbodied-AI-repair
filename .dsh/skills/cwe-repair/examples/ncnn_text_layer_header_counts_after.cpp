// Reduced local fixture derived from PR-text层头校验修复.patch.
// Count guards do not establish that all header values came from one record.
int load_text_layer(DataReader& dr)
{
    char layer_type[256];
    char layer_name[256];
    int bottom_count = 0;
    int top_count = 0;
    SCAN_VALUE("%255s", layer_type)
    SCAN_VALUE("%255s", layer_name)
    SCAN_VALUE("%d", bottom_count)
    SCAN_VALUE("%d", top_count)
    if (bottom_count < 0 || top_count < 0 || bottom_count > MAX_BLOB_COUNT || top_count > MAX_BLOB_COUNT)
        return -1;
    layer->tops.resize(top_count);
    return 0;
}
