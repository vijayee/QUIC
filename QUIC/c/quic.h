#include <msquic.h>
#include "queue.h"
#if __linux__
  #include <pthread.h>
#endif
#if _WIN32
  #include <windows.h>
#endif
static QUIC_API_TABLE* MSQuic;
static size_t registration_count;
// Create a new registration object
// also initialize the apitable if it is uninitialized
HQUIC quic_new_registration(QUIC_REGISTRATION_CONFIG* config);
void quic_free_registration(HQUIC registration);
QUIC_REGISTRATION_CONFIG* quic_new_registration_config(const char* appName, int32_t executionProfile);
QUIC_CERTIFICATE_FILE*  quic_certificate_file(const char* privateKeyFile, const char* certificateFile);
QUIC_CERTIFICATE_FILE_PROTECTED* quic_certificate_file_protected(const char* certificateFile, const char* privateKeyFile, const char* privateKeyPassword);
QUIC_CERTIFICATE_PKCS12* quic_certificate_pkcs12(const uint8_t *Asn1Blob, uint32_t Asn1BlobLength, const char* privateKeyPassword);
void quic_free_certificate_file(QUIC_CERTIFICATE_FILE* cert);
void quic_free(void* ptr);
QUIC_CREDENTIAL_CONFIG* quic_new_credential_config(int32_t credType, uint64_t flags, void * cert, uint8_t allowedCiphers, const char* caCertificateFile);

struct quic_setting_value_uint64_t {
  uint64_t set;
  uint64_t value;
};

struct quic_setting_value_uint32_t {
  uint64_t set;
  uint32_t value;
};

struct quic_setting_value_uint16_t {
  uint64_t set;
  uint16_t value;
};

struct quic_setting_value_uint8_t {
  uint64_t set;
  uint8_t value;
};

QUIC_SETTINGS* quic_new_settings(struct quic_setting_value_uint64_t maxBytesPerKey,
    struct quic_setting_value_uint64_t handshakeIdleTimeoutMs,
    struct quic_setting_value_uint64_t idleTimeoutMs,
    struct quic_setting_value_uint64_t mtuDiscoverySearchCompleteTimeoutUs,
    struct quic_setting_value_uint32_t tlsClientMaxSendBuffer,
    struct quic_setting_value_uint32_t tlsServerMaxSendBuffer,
    struct quic_setting_value_uint32_t streamRecvWindowDefault,
    struct quic_setting_value_uint32_t streamRecvBufferDefault,
    struct quic_setting_value_uint32_t connFlowControlWindow,
    struct quic_setting_value_uint32_t maxWorkerQueueDelayUs,
    struct quic_setting_value_uint32_t maxStatelessOperations,
    struct quic_setting_value_uint32_t initialWindowPackets,
    struct quic_setting_value_uint32_t sendIdleTimeoutMs,
    struct quic_setting_value_uint32_t initialRttMs,
    struct quic_setting_value_uint32_t maxAckDelayMs,
    struct quic_setting_value_uint32_t disconnectTimeoutMs,
    struct quic_setting_value_uint32_t keepAliveIntervalMs,
    struct quic_setting_value_uint16_t congestionControlAlgorithm,
    struct quic_setting_value_uint16_t peerBidiStreamCount,
    struct quic_setting_value_uint16_t peerUnidiStreamCount,
    struct quic_setting_value_uint16_t maxBindingStatelessOperations,
    struct quic_setting_value_uint16_t dtatelessOperationExpirationMs,
    struct quic_setting_value_uint16_t minimumMtu,
    struct quic_setting_value_uint16_t maximumMtu,
    struct quic_setting_value_uint8_t sendBufferingEnabled,
    struct quic_setting_value_uint8_t pacingEnabled,
    struct quic_setting_value_uint8_t migrationEnabled,
    struct quic_setting_value_uint8_t datagramReceiveEnabled,
    struct quic_setting_value_uint8_t serverResumptionLevel,
    struct quic_setting_value_uint8_t greaseQuicBitEnabled,
    struct quic_setting_value_uint8_t ecnEnabled,
    struct quic_setting_value_uint8_t maxOperationsPerDrain,
    struct quic_setting_value_uint8_t mtuDiscoveryMissingProbeCount,
    struct quic_setting_value_uint32_t destCidUpdateIdleTimeoutMs);
HQUIC* quic_new_configuration(HQUIC registration, char** alpn, uint32_t alpnSize, QUIC_SETTINGS* settings);
void quic_configuration_load_credential(HQUIC* configuration, QUIC_CREDENTIAL_CONFIG* credentials);

typedef enum quic_event_type {
  QUIC_STREAM_EVENTS,
  QUIC_CONNECTION_EVENTS,
  QUIC_LISTENER_EVENTS
} quic_event_type;
struct quic_event_queue_node;
typedef struct quic_event_queue_node quic_event_queue_node;
struct quic_event_queue_node {
  quic_event_type type;
  TAILQ_ENTRY(quic_event_queue_node) next;
  void* event;
};
TAILQ_HEAD(QUEUE_START, quic_event_queue_node);
typedef struct QUEUE_START queue_start;
typedef struct {
   #if __linux__
     pthread_mutex_t lock;
   #endif
   #if _WIN32
     CRITICAL_SECTION lock;
   #endif
   queue_start next;
   int length;
} quic_event_queue;

quic_event_queue* quic_new_event_queue();


typedef struct  quic_server_event_context {
  quic_event_queue* events;
  void* serverActor;
  void* cb;
} quic_server_event_context;

typedef struct  quic_connection_event_context {
  quic_event_queue* events;
  void* connectionActor;
  uint8_t isClient;
  uint8_t QUIC_CONNECTION_EVENT_CONNECTED;
  void* cb;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_CONNECTED_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_CONNECTED_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE;
  #if __linux__
    pthread_mutex_t  QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_RESUMED;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_RESUMED_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_RESUMED_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED_LOCK;
  #endif
} quic_connection_event_context;

int quic_server_event_type_as_int(QUIC_LISTENER_EVENT* event);
HQUIC quic_server_listener_open(HQUIC registration, quic_server_event_context* ctx);
void quic_server_listener_close(HQUIC listener);
HQUIC quic_receive_connection(QUIC_LISTENER_EVENT* event);
uint32_t quic_connection_set_configuration(HQUIC connection, HQUIC* configuration);
void quic_connection_set_callback(HQUIC connection, void* connectionCallback, void* ctx);
void quic_send_resumption_ticket(HQUIC connection);
void quic_close_connection(HQUIC connection);
HQUIC quic_receive_stream(QUIC_CONNECTION_EVENT* event);
int quic_receive_stream_type(QUIC_CONNECTION_EVENT* event);
void quic_stream_set_callback(HQUIC stream, void* ctx);

uint32_t quic_stream_status_pending();



quic_server_event_context* quic_new_server_event_context(void* serverActor, void* cb, quic_event_queue* queue);



void* quic_server_actor(quic_server_event_context* ctx);

void* quic_connection_actor(quic_connection_event_context* ctx);

quic_connection_event_context* quic_new_connection_event_context(uint8_t isClient, void * cb, quic_event_queue* queue);
void quic_connection_event_context_set_actor(quic_connection_event_context* ctx, void* connectionActor);

void quic_free_connection_event_context(quic_connection_event_context* ctx);

HQUIC quic_connection_open(HQUIC registration, void* callback, quic_connection_event_context* ctx);
void quic_connection_set_connected_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_shutdown_initiated_by_transport_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_shutdown_initiated_by_peer_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_shutdown_complete_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_local_address_changed_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_peer_address_changed_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_peer_stream_started_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_streams_available_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_peer_needs_streams_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_ideal_processor_changed_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_datagram_state_changed_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_datagram_received_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_datagram_send_state_changed_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_resumed_changed_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_datagram_resumption_ticket_received_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_datagram_peer_certificate_received_event(quic_connection_event_context* ctx, uint8_t value);
uint8_t quic_connection_event_enabled(quic_connection_event_context* ctx, QUIC_CONNECTION_EVENT* event);
uint8_t quic_connection_connected_event_session_resumed(QUIC_CONNECTION_EVENT* event);
uint8_t quic_connection_connected_event_session_negotiated_alpn_length(QUIC_CONNECTION_EVENT* event);
void quic_connection_connected_event_session_negotiated_alpn_data(QUIC_CONNECTION_EVENT* event, uint8_t* buffer);
struct shutdown_initiated_by_transport_data {
  uint32_t status;
  uint64_t errorCode;
};
uint32_t quic_connection_shutdown_initiated_by_transport_data_status(QUIC_CONNECTION_EVENT* event);
uint64_t quic_connection_shutdown_initiated_by_transport_data_error_code(QUIC_CONNECTION_EVENT* event);
uint64_t quic_connection_shutdown_initiated_by_peer_data(QUIC_CONNECTION_EVENT* event);
struct shutdown_complete_data {
  uint8_t handshakeCompleted;
  uint8_t peerAcknowledgedShutdown;
  uint8_t appCloseInProgress;
};
void quic_connection_shutdown_complete_data(QUIC_CONNECTION_EVENT* event, struct shutdown_complete_data* data);
QUIC_ADDR* quic_connection_event_local_address_changed_data(QUIC_CONNECTION_EVENT* event);
QUIC_ADDR* quic_connection_event_peer_address_changed_data(QUIC_CONNECTION_EVENT* event);

struct streams_available_data {
  uint16_t bidirectionalCount;
  uint16_t unidirectionalCount;
};
void quic_connection_event_streams_available_data(QUIC_CONNECTION_EVENT* event, struct streams_available_data* data);
uint8_t quic_connection_event_peer_needs_streams_data(QUIC_CONNECTION_EVENT* event);
uint16_t quic_connection_event_ideal_processor_changed_data(QUIC_CONNECTION_EVENT* event);
uint32_t quic_connection_event_datagram_send_state_changed_data(QUIC_CONNECTION_EVENT* event);
uint32_t quic_connection_event_datagram_received_flags(QUIC_CONNECTION_EVENT* event);
uint32_t quic_connection_event_datagram_received_buffer_length(QUIC_CONNECTION_EVENT* event);
struct datagram_state_changed_data {
  uint8_t sendEnabled;
  uint16_t maxSendLength;
};
void quic_connection_event_datagram_state_changed_data(QUIC_CONNECTION_EVENT* event, struct datagram_state_changed_data* data);
uint16_t quic_connection_event_resumed_resumption_state_length(QUIC_CONNECTION_EVENT* event);
void quic_connection_event_resumed_resumption_state_buffer(QUIC_CONNECTION_EVENT* event, uint8_t* buffer);
uint32_t quic_connection_event_resumption_ticket_received_resumption_ticket_length(QUIC_CONNECTION_EVENT* event);
void quic_connection_event_resumption_ticket_received_resumption_ticket(QUIC_CONNECTION_EVENT* event, uint8_t* buffer);

typedef struct  quic_stream_event_context {
  quic_event_queue* events;
  void* streamActor;
  void* cb;
} quic_stream_event_context;

quic_stream_event_context* quic_stream_new_event_context();

void quic_stream_event_context_set_actor(quic_stream_event_context* ctx, void* streamActor);
void * quic_stream_actor(quic_stream_event_context* ctx);
uint64_t quic_stream_get_total_buffer_length(QUIC_STREAM_EVENT* event);
void quic_stream_get_total_buffer(QUIC_STREAM_EVENT* event, uint8_t* buffer, HQUIC stream);

struct stream_start_complete_data {
  uint32_t status;
  uint64_t id;
  uint8_t peerAccepted;
};
int quic_get_stream_event_type_as_int(QUIC_STREAM_EVENT* event);
void quic_stream_start_complete_data(QUIC_STREAM_EVENT* event, struct stream_start_complete_data* data);
uint8_t quic_stream_event_send_complete_canceled(QUIC_STREAM_EVENT* event);
uint64_t quic_stream_event_peer_send_aborted_error_code(QUIC_STREAM_EVENT* event);
uint64_t quic_stream_event_peer_receive_aborted_error_code(QUIC_STREAM_EVENT* event);
uint8_t quic_stream_event_send_shutdown_complete_graceful(QUIC_STREAM_EVENT* event);

struct stream_shutdown_complete_data {
  uint8_t connectionShutdown;
  uint8_t appCloseInProgress;
  uint8_t connectionShutdownByApp;
  uint8_t connectionClosedRemotely;
  uint64_t connectionErrorCode;
  uint32_t connectionCloseStatus;
};

void quic_stream_shutdown_complete_data(QUIC_STREAM_EVENT* event, struct stream_shutdown_complete_data* data);
uint64_t quic_stream_event_ideal_send_buffer_size_byte_count(QUIC_STREAM_EVENT* event);
HQUIC quic_stream_open_stream(HQUIC connection, QUIC_STREAM_OPEN_FLAGS flag, void* ctx);
void quic_stream_close_stream(HQUIC stream);
void quic_stream_start_stream(HQUIC stream, QUIC_STREAM_START_FLAGS flag);
void quic_stream_send(HQUIC stream, uint8_t* buffer, size_t bufferLength);
void quic_stream_shutdown(HQUIC stream, QUIC_STREAM_SHUTDOWN_FLAGS flag);
void quic_connection_start(HQUIC connection, HQUIC* configuration, int family, char * target, uint16_t port);
void quic_connection_set_resumption_ticket(HQUIC connection, uint8_t * ticket, uint32_t ticketLength);
void quic_connection_shutdown(HQUIC connection);
void quic_connection_close(HQUIC connection);

uint8_t quic_server_resumption_no_resume();
uint8_t quic_server_resumption_resume_only();
uint8_t quic_server_resumption_resume_and_zerortt();
void quic_server_listener_start(HQUIC listener, char** alpn, uint32_t alpnSize, int family, char* ip, char* port);
int quic_address_family_unspecified();
int quic_address_family_inet();
int quic_address_family_inet6();
void quic_server_listener_stop(HQUIC listener);
void quic_configuration_close(HQUIC* configuration);
uint8_t quic_connection_is_client(quic_connection_event_context* ctx);
void quic_enqueue_event(quic_event_queue* queue, void* event, quic_event_type type);
void* quic_dequeue_event(quic_event_queue* queue, uint8_t type);
void quic_stream_free_event(QUIC_STREAM_EVENT* event);
void quic_connection_free_event(QUIC_CONNECTION_EVENT* event);
int quic_get_connection_event_type_as_int(QUIC_CONNECTION_EVENT* event);
void printQueue(quic_event_queue* queue);
