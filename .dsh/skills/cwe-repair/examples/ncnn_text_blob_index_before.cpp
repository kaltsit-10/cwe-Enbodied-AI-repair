// Reduced candidate fixture derived from local NCNN text F1 record.
int load_text_blob(int blob_index, int blob_count)
{
    Blob& blob = d->blobs[blob_index];
    use(blob);
    return 0;
}
