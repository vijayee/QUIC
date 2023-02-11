use @quic_new_configuration[Pointer[None] tag](registration:Pointer[None] tag, alpn: Pointer[Pointer[U8]], alpnSize: U32, settings: Pointer[None])?
use @quic_new_settings[Pointer[None] tag](maxBytesPerKey: Pointer[U64] tag,
    handshakeIdleTimeoutMs: Pointer[U64] tag,
    idleTimeoutMs: Pointer[U64] tag,
    mtuDiscoverySearchCompleteTimeoutUs: Pointer[U64] tag,
    tlsClientMaxSendBuffer: Pointer[U32] tag,
    tlsServerMaxSendBuffer: Pointer[U32] tag,
    streamRecvWindowDefault: Pointer[U32] tag,
    streamRecvBufferDefault: Pointer[U32] tag,
    connFlowControlWindow: Pointer[U32] tag,
    maxWorkerQueueDelayUs: Pointer[U32] tag,
    maxStatelessOperations: Pointer[U32] tag,
    initialWindowPackets: Pointer[U32] tag,
    sendIdleTimeoutMs: Pointer[U32] tag,
    initialRttMs: Pointer[U32] tag,
    maxAckDelayMs: Pointer[U32] tag,
    disconnectTimeoutMs: Pointer[U32] tag,
    keepAliveIntervalMs: Pointer[U32] tag,
    congestionControlAlgorithm: Pointer[U16] tag,
    peerBidiStreamCount: Pointer[U16] tag,
    peerUnidiStreamCount: Pointer[U16] tag,
    maxBindingStatelessOperations: Pointer[U16] tag,
    statelessOperationExpirationMs: Pointer[U16] tag,
    minimumMtu: Pointer[U16] tag,
    maximumMtu: Pointer[U16] tag,
    sendBufferingEnabled: Pointer[U8] tag,
    pacingEnabled: Pointer[U8] tag,
    migrationEnabled: Pointer[U8] tag,
    datagramReceiveEnabled: Pointer[U8] tag,
    serverResumptionLevel: Pointer[U8] tag,
    greaseQuicBitEnabled: Pointer[U8] tag,
    ecnEnabled: Pointer[U8] tag,
    maxOperationsPerDrain: Pointer[U8] tag,
    mtuDiscoveryMissingProbeCount: Pointer[U8] tag,
    destCidUpdateIdleTimeoutMs: Pointer[U8] tag)
use @quic_configuration_load_credential[None](configuration: Pointer[None] tag, credentials: Pointer[None] tag)?
-

class QUICConfiguration
  config: Pointer[None] tag
  new create(registration: QUICRegistration, alpn: Array[String], settings: QUICSettings, credential: QUICCredential) ? =>
    let quicsettings: Pointer[None] tag = @quic_new_settings(
      try addressof (settings.maxBytesPerKey as U64) else Pointer[U64].create() end,
      try addressof (settings.handshakeIdleTimeoutMs as U64) else Pointer[U64].create() end,
      try addressof (settings.idleTimeoutMs as U64) else Pointer[U64].create() end,
      try addressof (settings.mtuDiscoverySearchCompleteTimeoutUs as U64) else Pointer[U64].create() end,
      try addressof (settings.tlsClientMaxSendBuffer as U32) else Pointer[U32].create() end,
      try addressof (settings.tlsServerMaxSendBuffer as U32) else Pointer[U32].create() end,
      try addressof (settings.streamRecvWindowDefault as U32) else Pointer[U32].create() end,
      try addressof (settings.streamRecvBufferDefault as U32) else Pointer[U32].create() end,
      try addressof (settings.connFlowControlWindow as U32) else Pointer[U32].create() end,
      try addressof (settings.maxWorkerQueueDelayUs as U32) else Pointer[U32].create() end,
      try addressof (settings.maxStatelessOperations as U32) else Pointer[U32].create() end,
      try addressof (settings.initialWindowPackets as U32) else Pointer[U32].create() end,
      try addressof (settings.sendIdleTimeoutMs as U32) else Pointer[U32].create() end,
      try addressof (settings.initialRttMs as U32) else Pointer[U32].create() end,
      try addressof (settings.maxAckDelayMs as U32) else Pointer[U32].create() end,
      try addressof (settings.disconnectTimeoutMs as U32) else Pointer[U32].create() end,
      try addressof (settings.keepAliveIntervalMs as U32) else Pointer[U32].create() end,
      try addressof (settings.congestionControlAlgorithm as U16) else Pointer[U16].create() end,
      try addressof (settings.peerBidiStreamCount as U16) else Pointer[U16].create() end,
      try addressof (settings.peerUnidiStreamCount as U16) else Pointer[U16].create() end,
      try addressof (settings.maxBindingStatelessOperations as U16) else Pointer[U16].create() end,
      try addressof (settings.statelessOperationExpirationMs as U16) else Pointer[U16].create() end,
      try addressof (settings.minimumMtu as U16) else Pointer[U16].create() end,
      try addressof (settings.maximumMtu as U16) else Pointer[U16].create() end,
      try addressof (settings.sendBufferingEnabled as Bool).u8() else Pointer[U8].create() end,
      try addressof (settings.pacingEnabled as Bool).u8() else Pointer[U8].create() end,
      try addressof (settings.migrationEnabled as Bool).u8() else Pointer[U8].create() end,
      try addressof (settings.datagramReceiveEnabled as Bool).u8() else Pointer[U8].create() end,
      try addressof (settings.serverResumptionLevel as Bool).u8() else Pointer[U8].create() end,
      try addressof (settings.greaseQuicBitEnabled as Bool).u8() else Pointer[U8].create() end,
      try addressof (settings.ecnEnabled as Bool).u8() else Pointer[U8].create() end,
      try addressof (settings.maxOperationsPerDrain as U8) else Pointer[U8].create() end,
      try addressof (settings.maxOperationsPerDrain as U8) else Pointer[U8].create() end,
      try addressof (settings.mtuDiscoveryMissingProbeCount as U8) else Pointer[U8].create() end,
      try addressof (settings.destCidUpdateIdleTimeoutMs as U8) else Pointer[U8].create() end
      )
      let alpn': Array[Pointer[U8] tag] = Array[Pointer[U8] tag]
      for app in alpn.values() do
        alpn'.push(app.cstring())
      end
      try
        config = @quic_new_configuration(registration.registration, alpn'.cpointer(), alpn.size().u32(), quicsettings)?
        @quic_free(quicsettings)
        @quic_configuration_load_credential(config, credentials)?
        @quic_free(quicsettings)
      else
        @quic_free(quicsettings)
      end
