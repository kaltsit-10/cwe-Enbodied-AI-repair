struct Backend;
struct Owner {
    void register_callback(void (*)());
    void unregister_callback(void (*)());
    Backend* create_backend();
};

int init(Owner* owner, Backend*& backend, bool& initialized)
{
    owner->register_callback(nullptr);
    backend = owner->create_backend();
    if (!backend)
    {
        owner->unregister_callback(nullptr);
        initialized = false;
        return -1;
    }
    initialized = true;
    return 0;
}

void on_run(Backend* backend, bool initialized)
{
    if (!initialized || !backend)
        return;
    backend->run();
}
