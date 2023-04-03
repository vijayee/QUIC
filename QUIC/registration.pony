use "lib:numa"
use "lib:msquic"
use "lib:ponyquic"
use "net"

primitive LowLatency
primitive MaxThroughput
primitive Scavenger
primitive RealTime
type QUICAuth is (AmbientAuth | NetAuth | UDPAuth)
type QUICExecutionProfile is (LowLatency | MaxThroughput | Scavenger | RealTime)

class val QUICRegistration
  let registration: Pointer[None] tag
  let config: Pointer[None] tag
  new create(auth: QUICAuth, appName: String, executionProfile: QUICExecutionProfile = LowLatency) ? =>
    config = match executionProfile
      | LowLatency =>
        @quic_new_registration_config(appName.cstring(), I32(0))
      | MaxThroughput =>
        @quic_new_registration_config(appName.cstring(), I32(1))
      | Scavenger =>
        @quic_new_registration_config(appName.cstring(), I32(2))
      | RealTime =>
        @quic_new_registration_config(appName.cstring(), I32(3))
    end
    registration = @quic_new_registration(config)?
  fun _final() =>
    @quic_free_registration(registration)
    @quic_free(config)
