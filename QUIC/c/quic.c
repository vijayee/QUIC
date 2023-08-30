#include "quic.h"
#include <pony.h>
#include <string.h>
#include <stdio.h>
#if _WIN32
  #include <windows.h>
#else
  #include <pthread.h>
  #include <sys/socket.h>
  #include <netdb.h>
#endif
#include <msquic.h>





#if _WIN32
  void platform_lock(CRITICAL_SECTION lock) {
    EnterCriticalSection(&lock);
  }
  void platform_unlock(CRITICAL_SECTION lock) {
    LeaveCriticalSection(&lock);
  }
  void platform_lock_init(CRITICAL_SECTION lock) {
    InitializeCriticalSection(&lock);
  }
  void platform_lock_destroy(CRITICAL_SECTION lock) {
    DeleteCriticalSection(&lock, NULL);
  }f
  CRITICAL_SECTION MSQuicLock;
#else
  void platform_lock(pthread_mutex_t lock) {
    pthread_mutex_lock(&lock);
  }
  void platform_unlock(pthread_mutex_t lock) {
    pthread_mutex_unlock(&lock);
  }
  void platform_lock_init(pthread_mutex_t lock) {
    pthread_mutex_init(&lock, NULL);
  }

  void platform_lock_destroy(pthread_mutex_t lock) {
    int result = pthread_mutex_destroy(&lock);
  }
  pthread_mutex_t MSQuicLock = PTHREAD_MUTEX_INITIALIZER;
#endif


HQUIC quic_new_registration(QUIC_REGISTRATION_CONFIG* config) {
  if (MSQuic == NULL) {
    #if _WIN32
    if (NULL == MSQuicLock.DebugInfo) {
      platform_lock_init(MSQuicLock);
    }
    #endif
    platform_lock(MSQuicLock);
    if (QUIC_FAILED(MsQuicOpen2(&MSQuic))) {
      pony_error();
      platform_unlock(MSQuicLock);
      return NULL;
    }
    platform_unlock(MSQuicLock);
  }

  platform_lock(MSQuicLock);
  HQUIC registration = NULL;

  if (QUIC_FAILED(MSQuic->RegistrationOpen(config, &registration))) {
        pony_error();
        platform_unlock(MSQuicLock);
        return NULL;
  } else {
    registration_count++;
  }
  platform_unlock(MSQuicLock);

  return registration;
}

QUIC_REGISTRATION_CONFIG* quic_new_registration_config(const char * appName, int32_t executionProfile) {
  QUIC_REGISTRATION_CONFIG* config = malloc(sizeof(QUIC_REGISTRATION_CONFIG));
  config->AppName= appName;
  config->ExecutionProfile= executionProfile;
  return config;
}
void quic_free(void* ptr) {
  free(ptr);
}

void quic_free_registration(HQUIC registration) {
  MSQuic->RegistrationClose(registration);
  registration_count--;
}

QUIC_CERTIFICATE_FILE*  quic_certificate_file(const char* privateKeyFile, const char* certificateFile) {
  QUIC_CERTIFICATE_FILE* cert = malloc(sizeof(QUIC_CERTIFICATE_FILE));
  cert->PrivateKeyFile = privateKeyFile;
  cert->CertificateFile = certificateFile;
  return cert;
}

QUIC_CERTIFICATE_FILE_PROTECTED* quic_certificate_file_protected(const char* certificateFile, const char* privateKeyFile, const char* privateKeyPassword) {
  QUIC_CERTIFICATE_FILE_PROTECTED* cert = malloc(sizeof(QUIC_CERTIFICATE_FILE_PROTECTED));
  cert->PrivateKeyFile = privateKeyFile;
  cert->CertificateFile = certificateFile;
  cert->PrivateKeyPassword = privateKeyPassword;
  return cert;
}

QUIC_CERTIFICATE_PKCS12* quic_certificate_pkcs12(const uint8_t *asn1Blob, uint32_t asn1BlobLength, const char* privateKeyPassword) {
  QUIC_CERTIFICATE_PKCS12* cert = malloc(sizeof(QUIC_CERTIFICATE_PKCS12));
  cert->Asn1Blob = asn1Blob;
  cert->Asn1BlobLength = asn1BlobLength;
  cert->PrivateKeyPassword = privateKeyPassword;
  return cert;
}

QUIC_CREDENTIAL_CONFIG* quic_new_credential_config(int32_t credType, uint64_t flags, void * cert, uint8_t allowedCiphers, const char* caCertificateFile) {
  QUIC_CREDENTIAL_CONFIG* cred = calloc(1, sizeof(QUIC_CREDENTIAL_CONFIG));
  cred->Type = credType;
  cred->Flags = flags;
  switch(credType){
    case 4:
      cred->CertificateFile = cert;
      break;
    case 5:
      cred->CertificateFileProtected = cert;
      break;
    case 6:
      cred->CertificatePkcs12 = cert;
      break;
  }
  cred->AllowedCipherSuites = allowedCiphers;
  cred->CaCertificateFile = caCertificateFile;
  return cred;
}

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
  struct quic_setting_value_uint16_t statelessOperationExpirationMs,
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
  struct quic_setting_value_uint32_t destCidUpdateIdleTimeoutMs) {

  int result = false;
  QUIC_SETTINGS* settings = calloc(1, sizeof(QUIC_SETTINGS));
  settings->MaxBytesPerKey = maxBytesPerKey.value;
  settings->IsSet.MaxBytesPerKey = maxBytesPerKey.set;

  settings->HandshakeIdleTimeoutMs = handshakeIdleTimeoutMs.value;
  settings->IsSet.HandshakeIdleTimeoutMs = handshakeIdleTimeoutMs.set;

  settings->IdleTimeoutMs = idleTimeoutMs.value;
  settings->IsSet.IdleTimeoutMs = idleTimeoutMs.set;

  settings->MtuDiscoverySearchCompleteTimeoutUs = mtuDiscoverySearchCompleteTimeoutUs.value;
  settings->IsSet.IdleTimeoutMs = idleTimeoutMs.set;

  settings->TlsClientMaxSendBuffer = tlsClientMaxSendBuffer.value;
  settings->IsSet.TlsClientMaxSendBuffer = tlsClientMaxSendBuffer.set;

  settings->StreamRecvWindowDefault = streamRecvWindowDefault.value;
  settings->IsSet.StreamRecvWindowDefault = streamRecvWindowDefault.set;

  settings->StreamRecvBufferDefault = streamRecvBufferDefault.value;
  settings->IsSet.StreamRecvBufferDefault = streamRecvBufferDefault.set;

  settings->ConnFlowControlWindow = connFlowControlWindow.value;
  settings->IsSet.ConnFlowControlWindow = connFlowControlWindow.set;

  settings->MaxWorkerQueueDelayUs = maxWorkerQueueDelayUs.value;
  settings->IsSet.MaxWorkerQueueDelayUs = maxWorkerQueueDelayUs.set;

  settings->MaxStatelessOperations = maxStatelessOperations.value;
  settings->IsSet.MaxStatelessOperations = maxStatelessOperations.set;

  settings->MaxWorkerQueueDelayUs= maxWorkerQueueDelayUs.value;
  settings->IsSet.MaxWorkerQueueDelayUs = maxWorkerQueueDelayUs.set;

  settings->InitialWindowPackets = initialWindowPackets.value;
  settings->IsSet.InitialWindowPackets = initialWindowPackets.set;

  settings->SendIdleTimeoutMs = sendIdleTimeoutMs.value;
  settings->IsSet.SendIdleTimeoutMs = sendIdleTimeoutMs.set;

  settings->InitialRttMs = initialRttMs.value;
  settings->IsSet.InitialRttMs = initialRttMs.set;

  settings->MaxAckDelayMs = maxAckDelayMs.value;
  settings->IsSet.MaxAckDelayMs = maxAckDelayMs.set;

  settings->DisconnectTimeoutMs = disconnectTimeoutMs.value;
  settings->IsSet.DisconnectTimeoutMs = disconnectTimeoutMs.set;

  settings->KeepAliveIntervalMs = keepAliveIntervalMs.value;
  settings->IsSet.KeepAliveIntervalMs = keepAliveIntervalMs.set;

  settings->CongestionControlAlgorithm = congestionControlAlgorithm.value;
  settings->IsSet.CongestionControlAlgorithm = congestionControlAlgorithm.set;

  settings->PeerBidiStreamCount = peerBidiStreamCount.value;
  settings->IsSet.PeerBidiStreamCount = peerBidiStreamCount.set;

  settings->PeerUnidiStreamCount = peerUnidiStreamCount.value;
  settings->IsSet.PeerUnidiStreamCount = peerUnidiStreamCount.set;

  settings->MaxBindingStatelessOperations = maxBindingStatelessOperations.value;
  settings->IsSet.MaxBindingStatelessOperations = maxBindingStatelessOperations.set;

  settings->StatelessOperationExpirationMs = statelessOperationExpirationMs.value;
  settings->IsSet.StatelessOperationExpirationMs = statelessOperationExpirationMs.set;

  settings->MinimumMtu = minimumMtu.value;
  settings->IsSet.MinimumMtu = minimumMtu.set;

  settings->MaximumMtu = maximumMtu.value;
  settings->IsSet.MaximumMtu = maximumMtu.set;

  settings->SendBufferingEnabled = sendBufferingEnabled.value;
  settings->IsSet.SendBufferingEnabled = sendBufferingEnabled.set;

  settings->PacingEnabled = pacingEnabled.value;
  settings->IsSet.PacingEnabled = pacingEnabled.set;

  settings->MaxOperationsPerDrain = migrationEnabled.value;
  settings->IsSet.MaxOperationsPerDrain = migrationEnabled.set;

  settings->DatagramReceiveEnabled = datagramReceiveEnabled.value;
  settings->IsSet.DatagramReceiveEnabled = datagramReceiveEnabled.set;

  settings->ServerResumptionLevel = serverResumptionLevel.value;
  settings->IsSet.ServerResumptionLevel = serverResumptionLevel.set;

  settings->GreaseQuicBitEnabled = greaseQuicBitEnabled.value;
  settings->IsSet.GreaseQuicBitEnabled = greaseQuicBitEnabled.set;

  settings->EcnEnabled = ecnEnabled.value;
  settings->IsSet.EcnEnabled = ecnEnabled.set;

  settings->MaxOperationsPerDrain = maxOperationsPerDrain.value;
  settings->IsSet.MaxOperationsPerDrain = maxOperationsPerDrain.set;

  settings->MtuDiscoveryMissingProbeCount = mtuDiscoveryMissingProbeCount.value;
  settings->IsSet.MtuDiscoveryMissingProbeCount = mtuDiscoveryMissingProbeCount.set;

  settings->DestCidUpdateIdleTimeoutMs = destCidUpdateIdleTimeoutMs.value;
  settings->IsSet.DestCidUpdateIdleTimeoutMs = destCidUpdateIdleTimeoutMs.set;

  return settings;
}

HQUIC* quic_new_configuration(HQUIC registration, char** alpn, uint32_t alpnSize, QUIC_SETTINGS* settings) {
  HQUIC* configuration = malloc(sizeof(HQUIC));
  QUIC_BUFFER alpns[alpnSize];

  for (int i = 0; i < alpnSize; i++) {
    alpns[i] = (QUIC_BUFFER) { .Length = strlen(alpn[i]), .Buffer = (uint8_t*) alpn[i] };
  }

  if (QUIC_FAILED(MSQuic->ConfigurationOpen(registration, (const QUIC_BUFFER* const)&alpns, alpnSize, settings, sizeof(*settings), NULL, configuration))) {
    pony_error();
    return NULL;
  }
  return configuration;
}

void quic_configuration_load_credential(HQUIC* configuration, QUIC_CREDENTIAL_CONFIG* credentials) {
  if (QUIC_FAILED(MSQuic->ConfigurationLoadCredential(*configuration, credentials))) {
    pony_error();
  }
}


int quic_server_event_type_as_int(QUIC_LISTENER_EVENT* event) {
  return (int) event->Type;
}

HQUIC quic_server_listner_open(HQUIC registration, void* serverListenerCallback, quic_server_event_context* ctx) {
  HQUIC listener = NULL;

  if (QUIC_FAILED(MSQuic->ListenerOpen(registration, serverListenerCallback, ctx, listener))) {
    pony_error();
    return NULL;
  }
  return listener;
}
void quic_server_listener_close(HQUIC listener) {
  if (listener != NULL) {
    MSQuic->ListenerClose(listener);
  }
}

HQUIC quic_receive_connection(QUIC_LISTENER_EVENT* event) {
  return &event->NEW_CONNECTION.Connection;
}

uint32_t quic_connection_set_configuration(HQUIC connection, HQUIC* configuration) {
  return (uint32_t) MSQuic->ConnectionSetConfiguration(connection, *configuration);
}

int serverCb(HQUIC listener, void* context, QUIC_LISTENER_EVENT* event) {
  pony_register_thread();
  quic_server_event_context* ctx = (quic_server_event_context*) context;
  QUIC_LISTENER_EVENT* evt = calloc(1, sizeof(QUIC_LISTENER_EVENT));
  evt->Type = event->Type;
  switch (event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
      evt->NEW_CONNECTION.Connection = event->NEW_CONNECTION.Connection;
      QUIC_NEW_CONNECTION_INFO* info = malloc(sizeof(QUIC_NEW_CONNECTION_INFO));
      evt->NEW_CONNECTION.Info = info;
      info->QuicVersion = event->NEW_CONNECTION.Info->QuicVersion;
      QUIC_ADDR* localAddress = malloc(sizeof(QUIC_ADDR));
      localAddress = malloc(sizeof(QUIC_ADDR));
      memcpy(localAddress, event->NEW_CONNECTION.Info->LocalAddress, sizeof(QUIC_ADDR));
      info->LocalAddress = localAddress;
      QUIC_ADDR* remoteAddress = malloc(sizeof(QUIC_ADDR));
      memcpy(remoteAddress, info->RemoteAddress, sizeof(QUIC_ADDR));
      info->RemoteAddress = remoteAddress;
      info->CryptoBufferLength = event->NEW_CONNECTION.Info->CryptoBufferLength;
      info->ClientAlpnListLength = event->NEW_CONNECTION.Info->ClientAlpnListLength;
      info->ServerNameLength = event->NEW_CONNECTION.Info->ServerNameLength;
      info->NegotiatedAlpnLength = event->NEW_CONNECTION.Info->NegotiatedAlpnLength;
      info->CryptoBuffer = malloc((size_t) event->NEW_CONNECTION.Info->CryptoBufferLength);
      memcpy((void *)info->CryptoBuffer, event->NEW_CONNECTION.Info->CryptoBuffer, (size_t) evt->NEW_CONNECTION.Info->CryptoBufferLength);
      info->ClientAlpnList = malloc((size_t) event->NEW_CONNECTION.Info->ClientAlpnListLength);
      memcpy((void *)info->ClientAlpnList, event->NEW_CONNECTION.Info->ClientAlpnList,(size_t) evt->NEW_CONNECTION.Info->ClientAlpnListLength);
      info->NegotiatedAlpn = malloc((size_t) event->NEW_CONNECTION.Info->NegotiatedAlpnLength);
      memcpy((void *)info->NegotiatedAlpn, event->NEW_CONNECTION.Info->NegotiatedAlpn, (size_t) evt->NEW_CONNECTION.Info->NegotiatedAlpnLength);
      info->ServerName = malloc((size_t) event->NEW_CONNECTION.Info->ServerNameLength);
      memcpy((void *) info->ServerName, event->NEW_CONNECTION.Info->ServerName, (size_t) evt->NEW_CONNECTION.Info->ServerNameLength);
      break;
    case QUIC_LISTENER_EVENT_STOP_COMPLETE:
      evt->STOP_COMPLETE.AppCloseInProgress = event->STOP_COMPLETE.AppCloseInProgress;
      evt->STOP_COMPLETE.RESERVED = event->STOP_COMPLETE.RESERVED;
      break;
  }
  quic_enqueue_event(&ctx->events, evt, QUIC_LISTENER_EVENTS);
  void (*cb)(void*) = (void (*)(void*)) ctx->cb;
  (*cb)(ctx);
  return 0;
}

void quic_server_free_event(QUIC_LISTENER_EVENT* event) {
  switch (event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
      free(event->NEW_CONNECTION.Info);
      free(event->NEW_CONNECTION.Info->LocalAddress);
      free(event->NEW_CONNECTION.Info->RemoteAddress);
      free(event->NEW_CONNECTION.Info->CryptoBuffer);
      free(event->NEW_CONNECTION.Info->ClientAlpnList);
      free(event->NEW_CONNECTION.Info->NegotiatedAlpn);
      free(event->NEW_CONNECTION.Info->ServerName);
      break;
    case QUIC_LISTENER_EVENT_STOP_COMPLETE:
      free(event);
      break;
  }
}

HQUIC quic_server_listener_open(HQUIC registration, quic_server_event_context* ctx) {
  HQUIC listener = NULL;

  if (QUIC_FAILED(MSQuic->ListenerOpen(registration, serverCb, ctx, listener))) {
    pony_error();
  }
  return listener;
}

int quic_get_connection_event_type_as_int(QUIC_CONNECTION_EVENT* event) {
  switch (event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
      printf("QUIC_CONNECTION_EVENT_CONNECTED\n");
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
      printf("QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT\n");
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
      printf("QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER\n");
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
      printf("QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE\n");
      break;
    case QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED:
      printf("QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED\n");
      break;
    case QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED:
      printf("QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED\n");
      break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
      printf("QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED\n");
      break;
    case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
      printf("QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE\n");
      break;
    case QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS:
      printf("QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE\n");
      break;
    case QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED:
      printf("QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED\n");
      break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
      printf("QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED\n");
     break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
      printf("QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED\n");
      break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
      printf("QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED\n");
      break;
    case QUIC_CONNECTION_EVENT_RESUMED:
      printf("QUIC_CONNECTION_EVENT_RESUMED\n");
      break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
      printf("QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED\n");
      break;
    case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED:
      printf("QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED\n");
      break;
    default:
      printf("well wtf\n");
      break;
  }
  return (int) event->Type;
}

void quic_send_resumption_ticket(HQUIC connection) {
  MSQuic->ConnectionSendResumptionTicket(connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
}

void quic_close_connection(HQUIC connection) {
  MSQuic->ConnectionClose(connection);
}

void quic_connection_set_callback(HQUIC connection, void* connectionCallback, void* ctx) {
  MSQuic->SetCallbackHandler(connection, connectionCallback, ctx);
}

HQUIC quic_receive_stream(QUIC_CONNECTION_EVENT* event) {
  return &event->PEER_STREAM_STARTED.Stream;
}
void printStreamEventPointer(QUIC_STREAM_EVENT* event) {
  printf("Stream Event pointer: %p\n", event);
}
void* transferEvent(QUIC_STREAM_EVENT* event) {
  return (void *) event;
}
unsigned int streamCb(HQUIC stream, void* context, QUIC_STREAM_EVENT* event) {
  pony_register_thread();
  quic_stream_event_context* ctx = (quic_stream_event_context*) context;
  QUIC_STREAM_EVENT* evt = calloc(1, sizeof(QUIC_STREAM_EVENT));
  evt->Type = event->Type;
  switch (event->Type) {
    case QUIC_STREAM_EVENT_START_COMPLETE:
      evt->START_COMPLETE.Status = event->START_COMPLETE.Status;
      evt->START_COMPLETE.ID = event->START_COMPLETE.ID;
      evt->START_COMPLETE.PeerAccepted = event->START_COMPLETE.PeerAccepted;
      evt->START_COMPLETE.RESERVED = event->START_COMPLETE.RESERVED;
      printf("Start Complete pointer before enqueue: %p\n", evt);
      break;
    case QUIC_STREAM_EVENT_RECEIVE:
      evt->RECEIVE.AbsoluteOffset = event->RECEIVE.AbsoluteOffset;
      evt->RECEIVE.TotalBufferLength = event->RECEIVE.TotalBufferLength;
      evt->RECEIVE.BufferCount = event->RECEIVE.BufferCount;
      evt->RECEIVE.Flags = event->RECEIVE.Flags;
      QUIC_BUFFER* buffers = malloc(sizeof(QUIC_BUFFER) * evt->RECEIVE.BufferCount);
      for (int32_t i = 0; i < event->RECEIVE.BufferCount; i++) {
        buffers[i].Length = event->RECEIVE.Buffers[i].Length;
        buffers[i].Buffer = malloc((size_t)buffers[i].Length);
        memcpy(buffers[i].Buffer, event->RECEIVE.Buffers[i].Buffer, (size_t)buffers[i].Length);
      }
      evt->RECEIVE.Buffers = buffers;
      break;
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
      evt->SEND_COMPLETE.Canceled = event->SEND_COMPLETE.Canceled;
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
      evt->PEER_SEND_ABORTED.ErrorCode =  event->PEER_SEND_ABORTED.ErrorCode;
      break;
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
      evt->PEER_RECEIVE_ABORTED.ErrorCode = event->PEER_RECEIVE_ABORTED.ErrorCode;
      break;
    case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
      evt->SEND_SHUTDOWN_COMPLETE.Graceful = evt->SEND_SHUTDOWN_COMPLETE.Graceful;
      break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
      evt->SHUTDOWN_COMPLETE.ConnectionShutdown = event->SHUTDOWN_COMPLETE.ConnectionShutdown;
      evt->SHUTDOWN_COMPLETE.AppCloseInProgress = event->SHUTDOWN_COMPLETE.AppCloseInProgress;
      evt->SHUTDOWN_COMPLETE.ConnectionShutdownByApp = event->SHUTDOWN_COMPLETE.ConnectionShutdownByApp;
      evt->SHUTDOWN_COMPLETE.ConnectionClosedRemotely = event->SHUTDOWN_COMPLETE.ConnectionClosedRemotely;
      evt->SHUTDOWN_COMPLETE.RESERVED = event->SHUTDOWN_COMPLETE.RESERVED;
      evt->SHUTDOWN_COMPLETE.ConnectionErrorCode = event->SHUTDOWN_COMPLETE.ConnectionErrorCode;
      evt->SHUTDOWN_COMPLETE.ConnectionCloseStatus = event->SHUTDOWN_COMPLETE.ConnectionCloseStatus;
     break;
    case QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE:
      evt->IDEAL_SEND_BUFFER_SIZE.ByteCount = event->IDEAL_SEND_BUFFER_SIZE.ByteCount;
      break;
    case QUIC_STREAM_EVENT_PEER_ACCEPTED:
      break;
  }
  quic_enqueue_event(&ctx->events, evt, QUIC_STREAM_EVENTS);
  void (*cb)(void*) = (void (*)(void*)) ctx->cb;
  (*cb)(ctx);
  return 0;
}
void quic_stream_free_event(QUIC_STREAM_EVENT* event) {
  switch (event->Type) {
    case QUIC_STREAM_EVENT_START_COMPLETE:
      free(event);
      break;
    case QUIC_STREAM_EVENT_RECEIVE:
      for (int32_t i = 0; i < event->RECEIVE.BufferCount; i++) {
        free(event->RECEIVE.Buffers[i].Buffer);
      }
      free(event->RECEIVE.Buffers);
      free(event);
      break;
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
      free(event);
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
      free(event);
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
      free(event);
      break;
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
      free(event);
      break;
    case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
      free(event);
      break;
    case QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE:
      free(event);
      break;
    case QUIC_STREAM_EVENT_PEER_ACCEPTED:
      free(event);
      break;
  }
}

void quic_stream_set_callback(HQUIC stream, void* ctx) {
  return MSQuic->SetCallbackHandler(stream, streamCb, ctx);
}

uint32_t quic_receive_stream_type(QUIC_CONNECTION_EVENT* event) {
  return (uint32_t) event->PEER_STREAM_STARTED.Flags;
}

int quic_get_stream_event_type_as_int(QUIC_STREAM_EVENT* event) {
  /*
  switch (event->Type) {
    case QUIC_STREAM_EVENT_START_COMPLETE:
      printf("QUIC_STREAM_EVENT_START_COMPLETE\n");
      break;
    case QUIC_STREAM_EVENT_RECEIVE:
      printf("QUIC_STREAM_EVENT_RECEIVE\n");
      break;
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
      printf("QUIC_STREAM_EVENT_SEND_COMPLETE\n");
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
      printf("QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN\n");
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
      printf("QUIC_STREAM_EVENT_PEER_SEND_ABORTED\n");
      break;
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
      printf("QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED\n");
      break;
    case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
      printf("QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE\n");
      break;
    case QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE:
      printf("QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE\n");
      break;
    case QUIC_STREAM_EVENT_PEER_ACCEPTED:
      printf("QUIC_STREAM_EVENT_PEER_ACCEPTED\n");
      break;
  }*/
  return (int) event->Type;
}

uint32_t quic_stream_get_buffer_count(QUIC_STREAM_EVENT* event) {
  return event->RECEIVE.BufferCount;
}

uint64_t quic_stream_get_total_buffer_length(QUIC_STREAM_EVENT* event) {
  return event->RECEIVE.BufferCount;
}

uint32_t quic_stream_status_pending() {
  return (uint32_t) QUIC_STATUS_PENDING;
}

uint32_t min(uint32_t a, uint32_t b) {
  if (a < b) {
    return a;
  } else {
    return b;
  }
}
void quic_stream_get_total_buffer(QUIC_STREAM_EVENT* event, uint8_t* buffer, HQUIC stream) {
  uint64_t offset = event->RECEIVE.AbsoluteOffset;
  for (uint32_t i = 0; offset < sizeof(uint64_t) && i < event->RECEIVE.BufferCount; ++i) {
    uint32_t length = min((uint32_t)(sizeof(uint64_t) - offset), event->RECEIVE.Buffers[i].Length);
    memcpy(buffer + offset, event->RECEIVE.Buffers[i].Buffer, length);
    offset += length;
  }
  MSQuic->StreamReceiveComplete(stream, offset);
}

quic_connection_event_context* quic_new_connection_event_context(uint8_t isClient, void * cb) {
  quic_connection_event_context* ctx= calloc(1, sizeof(quic_connection_event_context));
  ctx->isClient = isClient;
  ctx->cb= cb;
  ctx->QUIC_CONNECTION_EVENT_CONNECTED = 1;
  ctx->QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED = 1;
  ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT =1;
  ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER = 1;
  ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE= 1;
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_CONNECTED_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_RESUMED_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED_LOCK);
  return ctx;
}

void quic_free_connection_event_context(quic_connection_event_context* ctx) {
  if (ctx != NULL) {
    platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_CONNECTED_LOCK);
    platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT_LOCK);
    platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER_LOCK);
    platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE_LOCK);
    platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED_LOCK);
    platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED_LOCK);
    platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED_LOCK);
    platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE_LOCK);
    platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS_LOCK);
    platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED_LOCK);
    platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED_LOCK);
    platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED_LOCK);
    platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED_LOCK);
    platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_RESUMED_LOCK);
    platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED_LOCK);
    platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED_LOCK);
    free(ctx);
  }
}

void quic_connection_event_context_set_actor(quic_connection_event_context* ctx, void* connectionActor) {
    ctx->connectionActor = connectionActor;
}
void printQueue(quic_event_queue* queue) {
   quic_event_queue_node* node = queue->next;
   printf("queue: ");
   while (node != NULL) {
     printf("%p -> ", node->event);
     node= node->next;
   }
   printf("\n");
}

void quic_enqueue_event(quic_event_queue* queue, void* event, quic_event_type type) {
  platform_lock(queue->lock);
  quic_event_queue_node* node = NULL;
  if (queue->next == NULL) {
    node = calloc(1, sizeof(quic_event_queue_node));
    node->type = type;
    node->event = event;
    node->next = NULL;
    queue->next = node;
    queue->current = node;
    queue->length = 1;
  } else {
    node = queue->next;
    while (node->next!= NULL) {
      node = node->next;
    }
    node->next = calloc(1, sizeof(quic_event_queue_node));
    node= node->next;
    node->type = type;
    node->next = NULL;
    node->event = event;
    queue->length++;
  }
  /*
  if (type == QUIC_STREAM_EVENTS){
    printf("From enqueue %p \n", event);
    printQueue(queue);
  }*/
  platform_unlock(queue->lock);
}

void* quic_dequeue_event(void* context, uint8_t type) {
  /*
  if (type == 2) {
    QUIC_STREAM_EVENT* evt = calloc(1, sizeof(QUIC_STREAM_EVENT));
    evt->Type = QUIC_STREAM_EVENT_START_COMPLETE;
    evt->START_COMPLETE.Status = 0;
    evt->START_COMPLETE.ID = 1;
    evt->START_COMPLETE.PeerAccepted = 1;
    evt->START_COMPLETE.RESERVED = 0;
    return evt;
  }*/
  quic_event_queue* queue = NULL;
  switch(type) {
    case 0:
      queue = &(((quic_connection_event_context*)context)->events);
      break;
    case 1:
      queue = &(((quic_server_event_context* )context)->events);
      break;
    case 2:
      queue = &(((quic_stream_event_context*)context)->events);
      break;

  }

  platform_lock(queue->lock);

  if (type == 2) {
    //printf("Stream Context pointer %p\n", context);
    printf("From dequeue\n");
    printQueue(queue);
  }
  quic_event_queue_node* node= NULL;
  if (queue->next == NULL) {
    pony_error();
    queue->length = 0;
    return node;
  } else {
    node = queue->current;
    queue->current = node->next;
    queue->length--;
    assert(queue->length >= 0);
  }
  void* event = node->event;
  //node->event = NULL;
  //free(node);
  if (type == 2) {
    printf("After dequeue\n");
    printQueue(queue);
  }

  platform_unlock(queue->lock);
  /*if (type == 2) {
    printf("Sent Stream Event %p\n", event);
  }*/
  return event;
}
unsigned int connectionCb(HQUIC connection, void* context, QUIC_CONNECTION_EVENT* event) {
  pony_register_thread();
  quic_connection_event_context* ctx = (quic_connection_event_context*) context;
  if (!quic_connection_event_enabled(context, event)) {
    return 0;
  }

  QUIC_CONNECTION_EVENT * evt = calloc(1, sizeof(QUIC_CONNECTION_EVENT));
  evt->Type = event->Type;
  switch(event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
      if (!quic_connection_is_client(ctx)) {
        quic_send_resumption_ticket(connection);
      }
      evt->CONNECTED.SessionResumed = event->CONNECTED.SessionResumed;
      evt->CONNECTED.NegotiatedAlpnLength = event->CONNECTED.NegotiatedAlpnLength;
      evt->CONNECTED.NegotiatedAlpn = malloc((size_t)evt->CONNECTED.NegotiatedAlpnLength);
      memcpy((void*)evt->CONNECTED.NegotiatedAlpn, event->CONNECTED.NegotiatedAlpn, (size_t)event->CONNECTED.NegotiatedAlpnLength);
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
      evt->SHUTDOWN_INITIATED_BY_TRANSPORT.Status = event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status;
      evt->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode = event->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode;
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
      evt->SHUTDOWN_INITIATED_BY_PEER.ErrorCode = evt->SHUTDOWN_INITIATED_BY_PEER.ErrorCode;
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
      evt->SHUTDOWN_COMPLETE.HandshakeCompleted = event->SHUTDOWN_COMPLETE.HandshakeCompleted;
      evt->SHUTDOWN_COMPLETE.PeerAcknowledgedShutdown = event->SHUTDOWN_COMPLETE.PeerAcknowledgedShutdown;
      evt->SHUTDOWN_COMPLETE.AppCloseInProgress = event->SHUTDOWN_COMPLETE.AppCloseInProgress;
      break;
    case QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED:
      evt->LOCAL_ADDRESS_CHANGED.Address= malloc(sizeof(QUIC_ADDR));
      memcpy((void*)evt->LOCAL_ADDRESS_CHANGED.Address, event->LOCAL_ADDRESS_CHANGED.Address, sizeof(QUIC_ADDR));
      break;
    case QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED:
      evt->PEER_ADDRESS_CHANGED.Address= malloc(sizeof(QUIC_ADDR));
      memcpy((void*)evt->PEER_ADDRESS_CHANGED.Address, event->PEER_ADDRESS_CHANGED.Address, sizeof(QUIC_ADDR));
      break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
      evt->PEER_STREAM_STARTED.Stream = event->PEER_STREAM_STARTED.Stream;
      evt->PEER_STREAM_STARTED.Flags = event->PEER_STREAM_STARTED.Flags;
      break;
    case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
      evt->STREAMS_AVAILABLE.BidirectionalCount = event->STREAMS_AVAILABLE.BidirectionalCount;
      evt->STREAMS_AVAILABLE.UnidirectionalCount = event->STREAMS_AVAILABLE.UnidirectionalCount;
      break;
    case QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS:
      evt->PEER_NEEDS_STREAMS.Bidirectional = event-> PEER_NEEDS_STREAMS.Bidirectional;
      break;
    case QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED:
      evt->IDEAL_PROCESSOR_CHANGED.IdealProcessor = event->IDEAL_PROCESSOR_CHANGED.IdealProcessor;
      break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
      evt->DATAGRAM_STATE_CHANGED.SendEnabled = event->DATAGRAM_STATE_CHANGED.SendEnabled;
      evt->DATAGRAM_STATE_CHANGED.MaxSendLength = event->DATAGRAM_STATE_CHANGED.MaxSendLength;
      break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
      evt->DATAGRAM_RECEIVED.Buffer = malloc(sizeof(QUIC_BUFFER));
      evt->DATAGRAM_RECEIVED.Flags = event->DATAGRAM_RECEIVED.Flags;
      memcpy((void*)evt->DATAGRAM_RECEIVED.Buffer, (void *)&event->DATAGRAM_RECEIVED.Buffer, sizeof(event->DATAGRAM_RECEIVED.Buffer)) ;
      memcpy((void*)evt->DATAGRAM_RECEIVED.Buffer->Buffer, event->DATAGRAM_RECEIVED.Buffer->Buffer, (size_t) event->DATAGRAM_RECEIVED.Buffer->Length);
      break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
      evt->DATAGRAM_SEND_STATE_CHANGED.ClientContext = event->DATAGRAM_SEND_STATE_CHANGED.ClientContext;
      evt->DATAGRAM_SEND_STATE_CHANGED.State = event->DATAGRAM_SEND_STATE_CHANGED.State;
      break;
    case QUIC_CONNECTION_EVENT_RESUMED:
      evt->RESUMED.ResumptionStateLength = event->RESUMED.ResumptionStateLength;
      evt->RESUMED.ResumptionState = malloc((size_t) evt->RESUMED.ResumptionStateLength);
      memcpy((void*)evt->RESUMED.ResumptionState, event->RESUMED.ResumptionState, (size_t) evt->RESUMED.ResumptionStateLength);
      break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
      evt->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength = event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength;
      evt->RESUMPTION_TICKET_RECEIVED.ResumptionTicket = malloc((size_t) evt->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
      memcpy((void*)evt->RESUMPTION_TICKET_RECEIVED.ResumptionTicket, event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket, (size_t) evt->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
      break;
    case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED:
      break;
  }
  quic_enqueue_event(&ctx->events, evt, QUIC_CONNECTION_EVENTS);
  void (*cb)(void*) = (void (*)(void*)) ctx->cb;
  (*cb)(ctx);
  return 0;
}

void quic_connection_free_event(QUIC_CONNECTION_EVENT* event) {
  switch(event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
      free(event->CONNECTED.NegotiatedAlpn);
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
      free(event);
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
      free(event);
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
      free(event);
      break;
    case QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED:
      free(event->LOCAL_ADDRESS_CHANGED.Address);
      break;
    case QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED:
      free(event->PEER_ADDRESS_CHANGED.Address);
      break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
      free(event);
      break;
    case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
      free(event);
      break;
    case QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS:
      free(event);
      break;
    case QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED:
      free(event);
      break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
      free(event);
      break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
      free(event->DATAGRAM_RECEIVED.Buffer);
      free(event);
      break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
      free(event);
      break;
    case QUIC_CONNECTION_EVENT_RESUMED:
      free(event->RESUMED.ResumptionState);
      free(event);
      break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
      free(event);
      break;
    case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED:
      free(event);
      break;
  }
}

HQUIC quic_connection_open(HQUIC registration, void* callback, quic_connection_event_context* ctx) {
  HQUIC connection = NULL;
  if (QUIC_FAILED(MSQuic->ConnectionOpen(registration, (QUIC_CONNECTION_CALLBACK_HANDLER) connectionCb, ctx, &connection))) {
     pony_error();
     return NULL;
   }
   return connection;
}

quic_server_event_context* quic_new_server_event_context(void* serverActor, void* cb) {
  quic_server_event_context* ctx = calloc(1, sizeof(quic_server_event_context));
  ctx->serverActor = serverActor;
  ctx->cb = cb;
  return ctx;
}

void* quic_server_actor(quic_server_event_context* ctx) {
  return ctx->serverActor;
}


void quic_connection_set_connected_event(quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_CONNECTED_LOCK);
  ctx->QUIC_CONNECTION_EVENT_CONNECTED = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_CONNECTED_LOCK);
}

void quic_connection_set_shutdown_initiated_by_transport_event(quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT_LOCK);
  ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT_LOCK);
}

void quic_connection_set_shutdown_initiated_by_peer_event(quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER_LOCK);
  ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER_LOCK);
}

void quic_connection_set_shutdown_complete_event(quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE_LOCK);
  ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE_LOCK);
}

void quic_connection_set_local_address_changed_event(quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED_LOCK);
  ctx->QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED_LOCK);
}

void quic_connection_set_peer_address_changed_event(quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED_LOCK);
  ctx->QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED_LOCK);
}

void quic_connection_set_peer_stream_started_event(quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx-> QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED_LOCK);
  ctx-> QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED_LOCK);
}

void quic_connection_set_streams_available_event(quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE_LOCK);
  ctx->QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE_LOCK);
}

void quic_connection_set_peer_needs_streams_event(quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS_LOCK);
  ctx->QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS_LOCK);
}

void quic_connection_set_ideal_processor_changed_event(quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED_LOCK);
  ctx->QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED_LOCK);
}

void quic_connection_set_datagram_state_changed_event(quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED_LOCK);
  ctx->QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED_LOCK);
}

void quic_connection_set_datagram_received_event(quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED_LOCK);
  ctx->QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED_LOCK);
}

void quic_connection_set_datagram_send_state_changed_event(quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED_LOCK);
  ctx->QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED_LOCK);
}

void quic_connection_set_resumed_changed_event(quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_RESUMED_LOCK);
  ctx->QUIC_CONNECTION_EVENT_RESUMED = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_RESUMED_LOCK);
}

void quic_connection_set_datagram_resumption_ticket_received_event(quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED_LOCK);
  ctx->QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED_LOCK);
}

void quic_connection_set_datagram_peer_certificate_received_event(quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED_LOCK);
  ctx->QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED_LOCK);
}

uint8_t quic_connection_connected_event_session_resumed(QUIC_CONNECTION_EVENT* event) {
  return (uint8_t) event->CONNECTED.SessionResumed;
}

uint8_t quic_connection_connected_event_session_negotiated_alpn_length(QUIC_CONNECTION_EVENT* event) {
  return event->CONNECTED.NegotiatedAlpnLength;
}

void quic_connection_connected_event_session_negotiated_alpn_data(QUIC_CONNECTION_EVENT* event, uint8_t* buffer) {
  memcpy(buffer, event->CONNECTED.NegotiatedAlpn, (size_t)event->CONNECTED.NegotiatedAlpnLength);
}

uint8_t quic_connection_event_enabled(quic_connection_event_context* ctx, QUIC_CONNECTION_EVENT* event) {
  uint8_t value = 0;
  switch (event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED :
        platform_lock(ctx->QUIC_CONNECTION_EVENT_CONNECTED_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_CONNECTED;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_CONNECTED_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED_LOCK);
        return value;
        break;
    case QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_RESUMED:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_RESUMED_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_RESUMED;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_RESUMED_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED_LOCK);
        break;
  }
  return value;
}

void* quic_connection_actor(quic_connection_event_context* ctx) {
  return ctx->connectionActor;
}

uint32_t quic_connection_shutdown_initiated_by_transport_data_status(QUIC_CONNECTION_EVENT* event) {
  return event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status;
}
;
uint64_t quic_connection_shutdown_initiated_by_transport_data_error_code(QUIC_CONNECTION_EVENT* event) {
  return event->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode;
}

uint64_t quic_connection_shutdown_initiated_by_peer_data(QUIC_CONNECTION_EVENT* event) {
  return event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode;
}

void quic_connection_shutdown_complete_data(QUIC_CONNECTION_EVENT* event, struct shutdown_complete_data* data) {
  data->handshakeCompleted = (uint8_t) event->SHUTDOWN_COMPLETE.HandshakeCompleted;
  data->peerAcknowledgedShutdown = (uint8_t) event->SHUTDOWN_COMPLETE.PeerAcknowledgedShutdown;
  data->appCloseInProgress = (uint8_t) event->SHUTDOWN_COMPLETE.AppCloseInProgress;
}

QUIC_ADDR* quic_connection_event_local_address_changed_data(QUIC_CONNECTION_EVENT* event) {
  QUIC_ADDR* addr = malloc(sizeof(event->LOCAL_ADDRESS_CHANGED.Address));
  memcpy(addr, &event->LOCAL_ADDRESS_CHANGED.Address, sizeof(event->LOCAL_ADDRESS_CHANGED.Address));
  return addr;
}

QUIC_ADDR* quic_connection_event_peer_address_changed_data(QUIC_CONNECTION_EVENT* event) {
  QUIC_ADDR* addr = malloc(sizeof(event->PEER_ADDRESS_CHANGED.Address));
  memcpy(addr, &event->PEER_ADDRESS_CHANGED.Address, sizeof(event->PEER_ADDRESS_CHANGED.Address));
  return addr;
}
void quic_connection_event_streams_available_data(QUIC_CONNECTION_EVENT* event, struct streams_available_data* data) {
  data->bidirectionalCount = event->STREAMS_AVAILABLE.BidirectionalCount;
  data->unidirectionalCount = event->STREAMS_AVAILABLE.UnidirectionalCount;
}

uint8_t quic_connection_event_peer_needs_streams_data(QUIC_CONNECTION_EVENT* event) {
  return (uint8_t)event->PEER_NEEDS_STREAMS.Bidirectional;
}

uint16_t quic_connection_event_ideal_processor_changed_data(QUIC_CONNECTION_EVENT* event) {
  return event->IDEAL_PROCESSOR_CHANGED.IdealProcessor;
}

uint32_t quic_connection_event_datagram_send_state_changed_data(QUIC_CONNECTION_EVENT* event) {
  return (uint32_t) event->DATAGRAM_SEND_STATE_CHANGED.State;
}

uint32_t quic_connection_event_datagram_received_flags(QUIC_CONNECTION_EVENT* event) {
  return (uint32_t) event->DATAGRAM_RECEIVED.Flags;
}

uint32_t quic_connection_event_datagram_received_buffer_length(QUIC_CONNECTION_EVENT* event) {
  return event->DATAGRAM_RECEIVED.Buffer->Length;
}

void quic_connection_event_datagram_received_buffer(QUIC_CONNECTION_EVENT* event, uint8_t* buffer) {
  memcpy(buffer, event->DATAGRAM_RECEIVED.Buffer->Buffer, (size_t) event->DATAGRAM_RECEIVED.Buffer->Length);
}
void quic_connection_event_datagram_state_changed_data(QUIC_CONNECTION_EVENT* event, struct datagram_state_changed_data* data) {
  data->sendEnabled = (uint8_t) event->DATAGRAM_STATE_CHANGED.SendEnabled;
  data->maxSendLength = event->DATAGRAM_STATE_CHANGED.MaxSendLength;
}

uint16_t quic_connection_event_resumed_resumption_state_length(QUIC_CONNECTION_EVENT* event) {
  return event->RESUMED.ResumptionStateLength;
}

void quic_connection_event_resumed_resumption_state_buffer(QUIC_CONNECTION_EVENT* event, uint8_t* buffer) {
  memcpy(buffer, event->RESUMED.ResumptionState, (size_t) event->RESUMED.ResumptionStateLength);
}

uint32_t quic_connection_event_resumption_ticket_received_resumption_ticket_length(QUIC_CONNECTION_EVENT* event) {
  return event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength;
}
void quic_connection_event_resumption_ticket_received_resumption_ticket(QUIC_CONNECTION_EVENT* event, uint8_t* buffer) {
  memcpy(buffer, event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket, (size_t) event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
}

quic_stream_event_context * quic_stream_new_event_context(void* cb) {
  quic_stream_event_context * ctx = calloc(1, sizeof(quic_stream_event_context));
  ctx->cb = cb;
  return ctx;
}

void quic_stream_event_context_set_actor(quic_stream_event_context* ctx, void* streamActor) {
  ctx->streamActor = streamActor;
}

void* quic_stream_actor(quic_stream_event_context* ctx) {
  return ctx->streamActor;
}

struct stream_start_complete_data quic_stream_start_complete_data(QUIC_STREAM_EVENT * event) {
  printf("Start Complete pointer: %p\n", event);
  struct stream_start_complete_data data;
  data.status = (uint32_t) event->START_COMPLETE.Status;
  data.id = event->START_COMPLETE.ID;
  data.peerAccepted = (uint8_t) event->START_COMPLETE.PeerAccepted;
  return data;
}

uint8_t quic_stream_event_send_complete_canceled(QUIC_STREAM_EVENT * event) {
  return (uint8_t) event->SEND_COMPLETE.Canceled;
}

uint64_t quic_stream_event_peer_send_aborted_error_code(QUIC_STREAM_EVENT * event) {
  return event->PEER_SEND_ABORTED.ErrorCode;
}

uint64_t quic_stream_event_peer_receive_aborted_error_code(QUIC_STREAM_EVENT * event) {
  return event->PEER_RECEIVE_ABORTED.ErrorCode;
}

uint8_t quic_stream_event_send_shutdown_complete_graceful(QUIC_STREAM_EVENT * event) {
  return (uint8_t) event->SEND_SHUTDOWN_COMPLETE.Graceful;
}

struct stream_shutdown_complete_data quic_stream_shutdown_complete_data(QUIC_STREAM_EVENT * event) {
  struct stream_shutdown_complete_data data;
  data.connectionShutdown = event->SHUTDOWN_COMPLETE.ConnectionShutdown;
  data.appCloseInProgress = event->SHUTDOWN_COMPLETE.AppCloseInProgress;
  data.connectionShutdownByApp = (uint8_t) event->SHUTDOWN_COMPLETE.ConnectionShutdownByApp;
  data.connectionClosedRemotely = (uint8_t) event->SHUTDOWN_COMPLETE.ConnectionClosedRemotely;
  data.connectionErrorCode = (uint8_t) event->SHUTDOWN_COMPLETE.ConnectionErrorCode;
  data.connectionCloseStatus = (uint8_t) event->SHUTDOWN_COMPLETE.ConnectionCloseStatus;
  return data;
}

uint64_t quic_stream_event_ideal_send_buffer_size_byte_count(QUIC_STREAM_EVENT * event) {
  return event->IDEAL_SEND_BUFFER_SIZE.ByteCount;
}

HQUIC quic_stream_open_stream(HQUIC connection, QUIC_STREAM_OPEN_FLAGS flag, void* ctx) {
  HQUIC stream = NULL;
  if (QUIC_FAILED(MSQuic->StreamOpen(connection, flag, streamCb, ctx, &stream))) {
    pony_error();
    return NULL;
  };
  return stream;
}

void quic_stream_close_stream(HQUIC stream) {
  MSQuic->StreamClose(stream);
}

void quic_stream_start_stream(HQUIC stream, QUIC_STREAM_START_FLAGS flag) {
  if (QUIC_FAILED(MSQuic->StreamStart(stream, flag))) {
    pony_error();
  };
}
void quic_stream_send(HQUIC stream, uint8_t* buffer, size_t bufferLength) {
  QUIC_BUFFER* sendBuffer = malloc(sizeof(QUIC_BUFFER));
  if (sendBuffer == NULL) {
    pony_error();
    return;
  }

  sendBuffer->Buffer = malloc(bufferLength);
  if (sendBuffer->Buffer  == NULL) {
    free(sendBuffer);
    pony_error();
    return;
  }
  memcpy(sendBuffer->Buffer, buffer, bufferLength);
  sendBuffer->Length = (uint32_t) bufferLength;
  if (QUIC_FAILED(MSQuic->StreamSend(stream, sendBuffer, 1, 0, sendBuffer))) {
    free(sendBuffer->Buffer);
    free(sendBuffer);
    pony_error();
  }
}

void quic_stream_shutdown(HQUIC stream, QUIC_STREAM_SHUTDOWN_FLAGS flag) {
  if (QUIC_FAILED(MSQuic->StreamShutdown(stream, flag, 0))) {
    pony_error();
  }
}

void quic_connection_start(HQUIC connection, HQUIC* configuration, int family, char * target, uint16_t port) {
  if (QUIC_FAILED(MSQuic->ConnectionStart(connection, *configuration, family, target, port))) {
    pony_error();
  }
}

void quic_connection_set_resumption_ticket(HQUIC connection, uint8_t * ticket, uint32_t ticketLength) {
  if(QUIC_FAILED(MSQuic->SetParam(connection, QUIC_PARAM_CONN_RESUMPTION_TICKET, ticketLength, ticket))) {
    pony_error();
  };
}

void quic_connection_shutdown(HQUIC connection) {
  MSQuic->ConnectionShutdown(connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
}

void quic_connection_close(HQUIC connection) {
  MSQuic->ConnectionClose(connection);
}

uint8_t quic_server_resumption_no_resume() {
  return (uint8_t) QUIC_SERVER_NO_RESUME;
}
uint8_t quic_server_resumption_resume_only() {
  return (uint8_t) QUIC_SERVER_RESUME_ONLY;
}
uint8_t quic_server_resumption_resume_and_zerortt() {
  return (uint8_t) QUIC_SERVER_RESUME_AND_ZERORTT;
};

void quic_server_listener_start(HQUIC listener, char** alpn, uint32_t alpnSize, int family, char* ip, char* port) {
  struct addrinfo hints;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags = AI_ADDRCONFIG;
  hints.ai_family = family;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  if((ip != NULL) && (ip[0] == '\0'))
    ip = NULL;

  struct addrinfo* result;

  if (getaddrinfo(ip, port, &hints, &result) != 0) {
    pony_error();
    return;
  }
  QUIC_ADDR address = {0};
  address.Ip = *result->ai_addr;

  QUIC_BUFFER alpns[alpnSize];

  for (int i = 0; i < alpnSize; i++) {
    alpns[i] = (QUIC_BUFFER) { .Length = strlen(alpn[i]), .Buffer = (uint8_t*) alpn[i] };
  }
  if (QUIC_FAILED(MSQuic->ListenerStart(listener, (const QUIC_BUFFER* const)&alpns, alpnSize, &address))) {
    freeaddrinfo(result);
    pony_error();
    return;
  }
  freeaddrinfo(result);
}

int quic_address_family_unspecified() {
  return AF_UNSPEC;
}

int quic_address_family_inet() {
  return AF_INET;
}

int quic_address_family_inet6() {
  return AF_INET6;
}

void quic_server_listener_stop(HQUIC listener) {
  MSQuic->ListenerStop(listener);
}

void quic_configuration_close(HQUIC* configuration) {
  MSQuic->ConfigurationClose(*configuration);
}
uint8_t quic_connection_is_client(quic_connection_event_context* ctx) {
  return ctx->isClient;
}
