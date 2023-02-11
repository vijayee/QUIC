use "lib:numa"
use "lib:msquic"
use "lib:ponyquic"
use "net"
use @quic_new_registration[Pointer[None] tag](config: Pointer[None] tag)?
use @quic_free_registration[None](registration: Pointer[None] tag)
use @quic_new_registration_config[Pointer[None] tag](appName: Pointer[U8 val] tag, executionProfile: I32)
use @quic_free[None](ptr: Pointer[None] tag)

primitive LowLatency
primitive MaxThroughput
primitive Scavenger
primitive RealTime
type QUICAuth is (AmbientAuth | NetAuth | UDPAuth)
type QUICExecutionProfile is (LowLatency | MaxThroughput | Scavenger | RealTime)

class QUICRegistration
  let registration: Pointer[None] tag
  let config: Pointer[None] tag
  new val create(auth: QUICAuth, appName: String, executionProfile: QUICExecutionProfile = LowLatency) ? =>
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
