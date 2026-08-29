// Reduced proposed fixed fixture derived from local NCNN text F1 record.
int load_text_blob(int blob_index, int blob_count)
{
    if (blob_index < 0 || blob_index >= blob_count)
        return -1;

    Blob& blob = d->blobs[blob_index];
    use(blob);
    return 0;
}
