use "Streams"
use "Exception"

actor QUICWriteableStream is WriteablePushStream[Array[U8] iso]
  var _isDestroyed: Bool = false
  let _subscribers': Subscribers
  var _ctx: Pointer[None] tag
  let _stream: Pointer[None] tag
  let _queue: Pointer[None] tag

  new _create(stream: Pointer[None] tag, ctx: Pointer[None] tag, queue: Pointer[None] tag) =>
    _stream = stream
    _subscribers' = Subscribers(3)
    _ctx = ctx
    _queue = queue

  fun ref subscribers(): Subscribers=>
    _subscribers'

  fun destroyed(): Bool =>
    _isDestroyed

  fun _final() =>
    @quic_stream_close_stream(_stream)
    @quic_free(_ctx)
    @quic_free(_queue)

  be _readEventQueue() =>
    try
      let event: Pointer[None] tag =  @quic_dequeue_event(_queue, 2)?
      match @quic_get_stream_event_type_as_int(event)
        //QUIC_STREAM_EVENT_START_COMPLETE
        | 0 =>
          var data': _StreamStartCompleteData = _StreamStartCompleteData
          @quic_stream_start_complete_data(event, data')
          var data: StreamStartCompleteData = StreamStartCompleteData(data'.status,
            data'.id,
            data'.peerAccepted == 1)
          _dispatchStreamStartComplete(data)
        //QUIC_STREAM_EVENT_RECEIVE
        | 1 =>
            _receive(event)
        //QUIC_STREAM_EVENT_SEND_COMPLETE
        | 2 =>
          let data: SendCompleteData = SendCompleteData(@quic_stream_event_send_shutdown_complete_graceful(event) == 1)
          _dispatchSendComplete(data)
        //QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN
        | 3 =>
          _dispatchPeerSendShutdown()
        //QUIC_STREAM_EVENT_PEER_SEND_ABORTED
        | 4 =>
          let data: PeerSendAbortedData = PeerSendAbortedData(@quic_stream_event_peer_send_aborted_error_code(event))
          _dispatchPeerSendAborted(data)
        //QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED
        | 5 =>
          let data: PeerReceiveAbortedData = PeerReceiveAbortedData(@quic_stream_event_peer_receive_aborted_error_code(event))
          _dispatchPeerReceiveAborted(data)
        //QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE
        | 6 =>
          let data: SendShutdownCompleteData = SendShutdownCompleteData(@quic_stream_event_send_shutdown_complete_graceful(event) == 1)
          _dispatchSendShutdownComplete(data)
        //QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE
        | 7 =>
          let data': _StreamShutdownCompleteData = _StreamShutdownCompleteData
          @quic_stream_shutdown_complete_data(event, data')
          let data: StreamShutdownCompleteData = StreamShutdownCompleteData(data'.connectionShutdown == 1,
            data'.appCloseInProgress == 1,
            data'.connectionShutdownByApp == 1,
            data'.connectionClosedRemotely == 1,
            data'.connectionErrorCode,
            data'.connectionCloseStatus)
          _dispatchStreamShutdownComplete(data)
        //QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE
        | 8 =>
          let data: IdealSendBufferSizeData = IdealSendBufferSizeData(@quic_stream_event_ideal_send_buffer_size_byte_count(event))
          _dispatchIdealSendBufferSize(data)
        //QUIC_STREAM_EVENT_PEER_ACCEPTED
        | 9 =>
          _dispatchPeerAccepted()
      end
      @quic_stream_free_event(event)
    end

  fun ref _receive(event: Pointer[None] tag) =>
    None

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
