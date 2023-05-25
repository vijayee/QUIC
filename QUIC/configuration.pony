struct QUICSettingValue[A: (U8 val | U16 val | U32 val | U64 val)]
  var set: U64
  var value: A
  new create(value': A, set': U64) =>
    set = set'
    value = value'

class val QUICConfiguration
  let config: Pointer[None] tag
  let alpn: Array[String] val
  new val create(registration: QUICRegistration, alpn': Array[String] val, settings: QUICSettings val, credentials: QUICCredentials) ? =>
    let quicsettings: Pointer[None] tag = @quic_new_settings(
      try QUICSettingValue[U64]((settings.maxBytesPerKey as U64), 1) else QUICSettingValue[U64](0,0) end,
      try QUICSettingValue[U64]((settings.handshakeIdleTimeoutMs as U64), 1) else QUICSettingValue[U64](0,0) end,
      try QUICSettingValue[U64]((settings.idleTimeoutMs as U64), 1) else QUICSettingValue[U64](0,0) end,
      try QUICSettingValue[U64]((settings.mtuDiscoverySearchCompleteTimeoutUs as U64), 1) else QUICSettingValue[U64](0,0) end,
      try QUICSettingValue[U32]((settings.tlsClientMaxSendBuffer as U32), 1) else QUICSettingValue[U32](0,0) end,
      try QUICSettingValue[U32]((settings.tlsServerMaxSendBuffer as U32), 1) else QUICSettingValue[U32](0,0) end,
      try QUICSettingValue[U32]((settings.streamRecvWindowDefault as U32), 1) else QUICSettingValue[U32](0,0) end,
      try QUICSettingValue[U32]((settings.streamRecvBufferDefault as U32), 1) else QUICSettingValue[U32](0,0) end,
      try QUICSettingValue[U32]((settings.connFlowControlWindow as U32), 1) else QUICSettingValue[U32](0,0) end,
      try QUICSettingValue[U32]((settings.maxWorkerQueueDelayUs as U32), 1) else QUICSettingValue[U32](0,0) end,
      try QUICSettingValue[U32]((settings.maxStatelessOperations as U32), 1) else QUICSettingValue[U32](0,0) end,
      try QUICSettingValue[U32]((settings.initialWindowPackets as U32), 1) else QUICSettingValue[U32](0,0) end,
      try QUICSettingValue[U32]((settings.sendIdleTimeoutMs as U32), 1) else QUICSettingValue[U32](0,0) end,
      try QUICSettingValue[U32]((settings.initialRttMs as U32), 1) else QUICSettingValue[U32](0,0) end,
      try QUICSettingValue[U32]((settings.maxAckDelayMs as U32), 1) else QUICSettingValue[U32](0,0) end,
      try QUICSettingValue[U32]((settings.disconnectTimeoutMs as U32), 1) else QUICSettingValue[U32](0,0) end,
      try QUICSettingValue[U32]((settings.keepAliveIntervalMs as U32), 1) else QUICSettingValue[U32](0,0) end,
      try QUICSettingValue[U16]((settings.congestionControlAlgorithm as U16), 1) else QUICSettingValue[U16](0,0) end,
      try QUICSettingValue[U16]((settings.peerBidiStreamCount as U16), 1) else QUICSettingValue[U16](0,0) end,
      try QUICSettingValue[U16]((settings.peerUnidiStreamCount as U16), 1) else QUICSettingValue[U16](0,0) end,
      try QUICSettingValue[U16]((settings.maxBindingStatelessOperations as U16), 1) else QUICSettingValue[U16](0,0) end,
      try QUICSettingValue[U16]((settings.statelessOperationExpirationMs as U16), 1) else QUICSettingValue[U16](0,0) end,
      try QUICSettingValue[U16]((settings.minimumMtu as U16), 1) else QUICSettingValue[U16](0,0) end,
      try QUICSettingValue[U16]((settings.maximumMtu as U16), 1) else QUICSettingValue[U16](0,0) end,
      try QUICSettingValue[U8](if (settings.sendBufferingEnabled as Bool) then 1 else 0 end, 1) else QUICSettingValue[U8](0,0) end,
      try QUICSettingValue[U8](if (settings.pacingEnabled as Bool) then 1 else 0 end, 1) else QUICSettingValue[U8](0,0) end,
      try QUICSettingValue[U8](if (settings.migrationEnabled as Bool) then 1 else 0 end, 1) else QUICSettingValue[U8](0,0) end,
      try QUICSettingValue[U8](if (settings.datagramReceiveEnabled as Bool) then 1 else 0 end, 1) else QUICSettingValue[U8](0,0) end,
      try QUICSettingValue[U8]((settings.serverResumptionLevel as U8), 1) else QUICSettingValue[U8](0,0) end,
      try QUICSettingValue[U8](if (settings.greaseQuicBitEnabled as Bool) then 1 else 0 end, 1) else QUICSettingValue[U8](0,0) end,
      try QUICSettingValue[U8](if (settings.ecnEnabled as Bool) then 1 else 0 end, 1) else QUICSettingValue[U8](0,0) end,
      try QUICSettingValue[U8]((settings.maxOperationsPerDrain as U8), 1) else QUICSettingValue[U8](0,0) end,
      try QUICSettingValue[U8]((settings.mtuDiscoveryMissingProbeCount as U8), 1) else QUICSettingValue[U8](0,0) end,
      try QUICSettingValue[U32]((settings.destCidUpdateIdleTimeoutMs as U32), 1) else QUICSettingValue[U32](0,0) end
      )
      let alpn'': Array[Pointer[U8] tag] = Array[Pointer[U8] tag](alpn'.size())
      for app in alpn'.values() do
        alpn''.push(app.cstring())
      end
      alpn = alpn'
      try
        config = @quic_new_configuration(registration.registration, alpn''.cpointer(), alpn''.size().u32(), quicsettings, QUICBuffer(0, Pointer[U8]))?
        @quic_configuration_load_credential(config, credentials.cred)?
        @quic_free(quicsettings)
      else
        config = Pointer[None]
        @quic_free(quicsettings)
        error
      end
    fun close() =>
      @quic_configuration_close(config)
    fun _final() =>
      @quic_configuration_close(config)
      @quic_free(config)
