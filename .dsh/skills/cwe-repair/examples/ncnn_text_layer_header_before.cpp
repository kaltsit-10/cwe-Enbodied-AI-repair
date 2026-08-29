// Reduced local fixture derived from the NCNN text layer-header record.
// The four scans are not accompanied by a same-record token-count contract.
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
    layer->tops.resize(top_count);
    return 0;
}
