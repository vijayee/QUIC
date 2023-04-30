use "Streams"
use "Exception"

actor QUICWriteableStream is WriteablePushStream[Array[U8] iso]
  var _isDestroyed: Bool = false
  let _subscribers': Subscribers
  let _ctx: Pointer[None] tag
  let _stream: Pointer[None] tag

  new _create(stream: Pointer[None] tag, ctx: Pointer[None] tag) =>
    _stream = stream
    _subscribers' = Subscribers(3)
    _ctx = ctx

  fun ref subscribers(): Subscribers=>
    _subscribers'

  fun destroyed(): Bool =>
    _isDestroyed

  fun _final() =>
    @quic_free(_ctx)
    @quic_stream_close_stream(_stream)

  be _dispatchStreamStartComplete(data: StreamStartCompleteData) =>
    notifyPayload[StreamStartCompleteData](StreamStartCompleteEvent, data)

  be _dispatchSendComplete(data: SendCompleteData) =>
    notifyPayload[SendCompleteData](SendCompleteEvent, data)

  be _dispatchPeerSendShutdown() =>
    notify(PeerSendShutdownEvent)

  be _dispatchPeerReceiveAborted(data: PeerReceiveAbortedData) =>
    _shutdown()
    notifyPayload[PeerReceiveAbortedData](PeerReceiveAbortedEvent, data)

  be _dispatchPeerSendAborted(data: PeerSendAbortedData) =>
    notifyPayload[PeerSendAbortedData](PeerSendAbortedEvent, data)

  be _dispatchSendShutdownComplete(data: SendShutdownCompleteData) =>
    notifyPayload[SendShutdownCompleteData](SendShutdownCompleteEvent, data)

  be _dispatchStreamShutdownComplete(data: StreamShutdownCompleteData) =>
    notifyPayload[StreamShutdownCompleteData](StreamShutdownCompleteEvent, data)

  be _dispatchIdealSendBufferSize(data: IdealSendBufferSizeData) =>
    notifyPayload[IdealSendBufferSizeData](IdealSendBufferSizeEvent, data)

  be _dispatchPeerAccepted() =>
    notify(PeerAcceptedEvent)

  be write(data: Array[U8] iso) =>
    if destroyed() then
      notifyError(Exception("Stream has been destroyed"))
    else
      let data': Array[U8] = consume data
      try
        @quic_stream_send(_stream, data'.cpointer(), data'.size())?
      else
        notifyError(Exception("Failed to write data"))
      end
    end

  be piped(stream: ReadablePushStream[Array[U8] iso] tag) =>
    if destroyed() then
      notifyError(Exception("Stream has been destroyed"))
    else
      let dataNotify: DataNotify[Array[U8] iso] iso = object iso is DataNotify[Array[U8] iso]
        let _stream: WriteablePushStream[Array[U8] iso] tag = this
        fun ref apply(data': Array[U8] iso) =>
          _stream.write(consume data')
      end
      stream.subscribe(consume dataNotify)
      let errorNotify: ErrorNotify iso = object iso is ErrorNotify
        let _stream: WriteablePushStream[Array[U8] iso] tag = this
        fun ref apply(ex: Exception) => _stream.destroy(ex)
      end
      stream.subscribe(consume errorNotify)
      let completeNotify: CompleteNotify iso = object iso is CompleteNotify
        let _stream: WriteablePushStream[Array[U8] iso] tag = this
        fun ref apply() => _stream.close()
      end
      stream.subscribe(consume completeNotify)
      let closeNotify: CloseNotify iso = object iso  is CloseNotify
        let _stream: WriteablePushStream[Array[U8] iso] tag = this
        fun ref apply () =>
          _stream.close()
      end
      let closeNotify': CloseNotify tag = closeNotify
      stream.subscribe(consume closeNotify)
      notifyPiped()
    end

  be destroy(message: (String | Exception)) =>
    match message
      | let message' : String =>
        notifyError(Exception(message'))
      | let message' : Exception =>
        notifyError(message')
    end
    _isDestroyed = true
    let subscribers': Subscribers = subscribers()
    subscribers'.clear()
    
  fun ref _close() =>
    if not destroyed() then
       @quic_stream_close_stream(_stream)
      _isDestroyed = true
      notifyClose()
      let subscribers': Subscribers = subscribers()
      subscribers'.clear()
    end

  fun ref _shutdown() =>
    try
      @quic_stream_shutdown(_stream, ShutdownAbort())?
    else
      notifyError(Exception("Stream failed to shutdown"))
    end
    _close()

  be close() =>
    if not destroyed() then
      _shutdown()
    end
