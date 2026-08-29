struct Backend;
struct Owner {
    void register_callback(void (*)());
    Backend* create_backend();
};

int init(Owner* owner, Backend*& backend)
{
    owner->register_callback(nullptr);
    backend = owner->create_backend();
    if (!backend)
        return -1;
    return 0;
}

void on_run(Backend* backend)
{
    backend->run();
}
