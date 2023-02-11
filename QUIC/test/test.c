#include <quic.h>

int main() {
    void* config = quic_new_registration_config("test", 3);
    void* registration = quic_new_registration(config);
    return 0;
}
