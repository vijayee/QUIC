use "Streams"
use "Exception"
use "collections"

type QUICStream is (QUICDuplexStream | QUICReadableStream | QUICWriteableStream)

primitive ShutdownGraceful
  fun apply(): U32 => 0x0001

primitive ShutdownAbortSend
  fun apply(): U32 => 0x0002

primitive ShutdownAbortReceive
  fun apply(): U32 => 0x0004

primitive ShutdownAbort
  fun apply(): U32 => 0x0006

primitive ShutdownImmediate
  fun apply(): U32 => 0x0008

primitive ShutdownInline
  fun apply(): U32 => 0x0010

type QUICStreamShutdownFlags is (ShutdownGraceful | ShutdownAbortSend | ShutdownAbortReceive | ShutdownAbort | ShutdownImmediate)

primitive _QUICStreamCallback
  fun apply(strm: Pointer[None] tag, context: Pointer[None] tag, event: Pointer[None] tag) : U32 =>
  let stream: QUICStream = @quic_stream_actor(context)
  match @quic_get_stream_event_type_as_uint(event)
    //QUIC_STREAM_EVENT_START_COMPLETE
    | 0 =>
      var data': _StreamStartCompleteData = @quic_stream_start_complete_data(event)
      var data: StreamStartCompleteData = StreamStartCompleteData(data'.status,
        data'.id,
        data'.peerAccepted == 1)
      stream._dispatchStreamStartComplete(data)
    //QUIC_STREAM_EVENT_RECEIVE
    | 1 =>
      match stream
        | let stream': QUICDuplexStream =>
          stream'._receive(event)
        | let stream': QUICReadableStream =>
          stream'._receive(event)
        else
          return 1
      end
      return @quic_stream_status_pending()
    //QUIC_STREAM_EVENT_SEND_COMPLETE
    | 2 =>
      let data: SendCompleteData = SendCompleteData(@quic_stream_event_send_shutdown_complete_graceful(event) == 1)
      stream._dispatchSendComplete(data)
    //QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN
    | 3 =>
      stream._dispatchPeerSendShutdown()
    //QUIC_STREAM_EVENT_PEER_SEND_ABORTED
    | 4 =>
      let data: PeerSendAbortedData = PeerSendAbortedData(@quic_stream_event_peer_send_aborted_error_code(event))
      stream._dispatchPeerSendAborted(data)
    //QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED
    | 5 =>
      let data: PeerReceiveAbortedData = PeerReceiveAbortedData(@quic_stream_event_peer_receive_aborted_error_code(event))
      stream._dispatchPeerReceiveAborted(data)
    //QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE
    | 6 =>
      let data: SendShutdownCompleteData = SendShutdownCompleteData(@quic_stream_event_send_shutdown_complete_graceful(event) == 1)
      stream._dispatchSendShutdownComplete(data)
    //QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE
    | 7 =>
      let data': _StreamShutdownCompleteData= @quic_stream_shutdown_complete_data(event)
      let data: StreamShutdownCompleteData = StreamShutdownCompleteData(data'.connectionShutdown == 1,
        data'.appCloseInProgress == 1,
        data'.connectionShutdownByApp == 1,
        data'.connectionClosedRemotely == 1,
        data'.connectionErrorCode,
        data'.connectionCloseStatus)
      stream._dispatchStreamShutdownComplete(data)
    //QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE
    | 8 =>
      let data: IdealSendBufferSizeData = IdealSendBufferSizeData(@quic_stream_event_ideal_send_buffer_size_byte_count(event))
      stream._dispatchIdealSendBufferSize(data)
    //QUIC_STREAM_EVENT_PEER_ACCEPTED
    | 9 =>
      stream._dispatchPeerAccepted()
  end
  0

actor QUICDuplexStream is DuplexPushStream[Array[U8] iso]
  var _readable: Bool = true
  var _writeable: Bool = true
  var _isDestroyed: Bool = false
  let _subscribers': Subscribers
  var _pipeNotifiers': (Array[Notify tag] iso | None) = None
  var _isPiped: Bool = false
  let _stream: Pointer[None] tag
  let _buffer: RingBuffer[U8]
  let _ctx: Pointer[None] tag
  var _auto : Bool = false

  new _create(stream: Pointer[None] tag, ctx: Pointer[None] tag) =>
    _subscribers' = Subscribers(3)
    _buffer = RingBuffer[U8](128000)
    _stream = stream
    _ctx = ctx

  fun ref subscribers(): Subscribers=>
    _subscribers'

  fun destroyed(): Bool =>
    _isDestroyed

  fun readable(): Bool =>
    _readable

  fun ref autoPush() : Bool =>
    _auto

  fun _final() =>
    @quic_free(_ctx)
    @quic_stream_close_stream(_stream)

  be _receive(event: Pointer[None] tag) =>
    let data: Array[U8] iso = recover
      let size: USize = @quic_stream_get_total_buffer_length(event).usize()
      let buffer: Pointer[U8] = @pony_alloc(@pony_ctx(), size)
      @quic_stream_get_total_buffer(event, buffer, _stream)
      let data': Array[U8] = Array[U8].from_cpointer(buffer, size)
      data'
    end

    let bufferEmpty: Bool = (_buffer.size() == 0)
    let hasDataSubscribers = (subscriberCount(DataEvent[Array[U8] iso]) > 0)
    if not hasDataSubscribers then
      let data': Array[U8] val = consume data
      for i in data'.values() do
        _buffer.push(i)
      end
      _auto = true
      return
    elseif hasDataSubscribers and bufferEmpty then
      let start: I64 = try ((_buffer.head()? + _buffer.size()) -? 1).i64() else 0 end
      let stop : I64 = try (_buffer.head()? -? 1).i64() else 0 end
      try
        for i in Range[I64](start, stop , -1) do
          data.unshift(_buffer(i.usize())?)
        end
        _buffer.clear()
      else
        notifyError(Exception("Buffer failed to clear"))
      end
    end
    notifyData(consume data)

  be _dispatchStreamStartComplete(data: StreamStartCompleteData) =>
    notifyPayload[StreamStartCompleteData](StreamStartCompleteEvent, data)

  be _dispatchSendComplete(data: SendCompleteData) =>
    notifyPayload[SendCompleteData](SendCompleteEvent, data)

  be _dispatchPeerSendShutdown() =>
    _readable = false
    notify(PeerSendShutdownEvent)

  be _dispatchSendShutdownComplete(data: SendShutdownCompleteData) =>
    notifyPayload[SendShutdownCompleteData](SendShutdownCompleteEvent, data)

  be _dispatchPeerReceiveAborted(data: PeerReceiveAbortedData) =>
    _writeable = false

    //TODO is this correct behavior?
    if not _readable and not _writeable then
      try
        @quic_stream_shutdown(_stream, ShutdownGraceful())?
        _writeable = false
      else
        notifyError(Exception("Stream failed to close"))
      end
      _close()
    end
    notifyPayload[PeerReceiveAbortedData](PeerReceiveAbortedEvent, data)

  be _dispatchPeerSendAborted(data: PeerSendAbortedData) =>
    _readable = false
    if (_buffer.size() == 0) and not _readable and not _writeable then
      try
        @quic_stream_shutdown(_stream, ShutdownGraceful())?
        _writeable = false
      else
        notifyError(Exception("Stream failed to close"))
      end
      _close()
    end
    notifyPayload[PeerSendAbortedData](PeerSendAbortedEvent, data)

  be _dispatchStreamShutdownComplete(data: StreamShutdownCompleteData) =>
    notifyPayload[StreamShutdownCompleteData](StreamShutdownCompleteEvent, data)

  be _dispatchIdealSendBufferSize(data: IdealSendBufferSizeData) =>
    notifyPayload[IdealSendBufferSizeData](IdealSendBufferSizeEvent, data)

  be _dispatchPeerAccepted() =>
    notify(PeerAcceptedEvent)

  be push() =>
    if destroyed() then
      notifyError(Exception("Stream has been destroyed"))
    elseif (not _readable) and (_buffer.size() == 0) then
      notifyError(Exception("Stream is closed for reading"))
    else
      if _buffer.size() == 0 then
        return
      end
      let size' = _buffer.size()
      let data = recover Array[U8](size') end
      try
        let stop: USize = _buffer.head()? + _buffer.size()
        for i in Range(_buffer.head()?, stop) do
          data.push(_buffer(i)?)
        end
        notifyData(consume data)
        _buffer.clear()
      else
        notifyError(Exception("Failed to read buffer"))
      end
    end

  be write(data: Array[U8] iso) =>
    if destroyed() then
      notifyError(Exception("Stream has been destroyed"))
    elseif not _writeable then
      notifyError(Exception("Stream is closed for writing"))
    else
      let data': Array[U8] = consume data
      try
        @quic_stream_send(_stream, data'.cpointer(), data'.size())?
      else
        notifyError(Exception("Failed to write data"))
      end
    end

  be read(cb: {(Array[U8] iso)} val, size: (USize | None) = None) =>
    if destroyed() then
      notifyError(Exception("Stream has been destroyed"))
    elseif not _readable then
      notifyError(Exception("Stream is closed for reading"))
    else
      var size' = match size
      | None => _buffer.size()
      | let size'': USize => size''
      end
      size' = size'.min(_buffer.size())

      let data = recover Array[U8](size') end

      try
        let stop = _buffer.head()? + size'
        for i in Range(_buffer.head()?, stop) do
          data.push(_buffer(i)?)
        end
        cb(consume data)
        try
          if stop < _buffer.size() then
            let buf = Array[U8](_buffer.size() - stop)
            for i' in Range(stop, _buffer.size()) do
              buf.push(_buffer(i')?)
            end
            _buffer.clear()
            for i'' in buf.values() do
              _buffer.push(i'')
            end
          end
        else
          notifyError(Exception("Failed to reset buffer"))
        end
      else
        notifyError(Exception("Failed to read buffer"))
      end
    end

  fun ref isPiped(): Bool =>
    _isPiped

  fun ref pipeNotifiers(): (Array[Notify tag] iso^ | None) =>
    _pipeNotifiers' = None

  be piped(stream: ReadablePushStream[Array[U8] iso] tag) =>
    if destroyed() then
      notifyError(Exception("Stream has been destroyed"))
    else
      let dataNotify: DataNotify[Array[U8] iso] iso = object iso is DataNotify[Array[U8] iso]
        let _stream: DuplexPushStream[Array[U8] iso] tag = this
        fun ref apply(data': Array[U8] iso) =>
          _stream.write(consume data')
      end
      stream.subscribe(consume dataNotify)
      let errorNotify: ErrorNotify iso = object iso is ErrorNotify
        let _stream: DuplexPushStream[Array[U8] iso] tag = this
        fun ref apply(ex: Exception) => _stream.destroy(ex)
      end
      stream.subscribe(consume errorNotify)
      let completeNotify: CompleteNotify iso = object iso is CompleteNotify
        let _stream: DuplexPushStream[Array[U8] iso] tag = this
        fun ref apply() => _stream.close()
      end
      stream.subscribe(consume completeNotify)
      let closeNotify: CloseNotify iso = object iso  is CloseNotify
        let _stream: DuplexPushStream[Array[U8] iso] tag = this
        fun ref apply () => _stream.close()
      end
      let closeNotify': CloseNotify tag = closeNotify
      stream.subscribe(consume closeNotify)
      notifyPiped()
    end

  be pipe(stream: WriteablePushStream[Array[U8] iso] tag) =>
    if destroyed() then
      notifyError(Exception("Stream has been destroyed"))
    else
      let pipeNotifiers': Array[Notify tag] iso = try
         pipeNotifiers() as Array[Notify tag] iso^
      else
        let pipeNotifiers'' = recover Array[Notify tag] end
        consume pipeNotifiers''
      end

      let pipedNotify: PipedNotify iso =  object iso is PipedNotify
        let _stream: DuplexPushStream[Array[U8] iso] tag = this
        fun ref apply() =>
          _stream.push()
      end
      let pipedNotify': PipedNotify tag = pipedNotify
      pipeNotifiers'.push(pipedNotify')
      stream.subscribe(consume pipedNotify)

      let errorNotify: ErrorNotify iso = object iso  is ErrorNotify
        let _stream: DuplexPushStream[Array[U8] iso] tag = this
        fun ref apply (ex: Exception) => _stream.destroy(ex)
      end
      let errorNotify': ErrorNotify tag = errorNotify
      pipeNotifiers'.push(errorNotify')
      stream.subscribe(consume errorNotify)

      let closeNotify: CloseNotify iso = object iso  is CloseNotify
        let _stream: DuplexPushStream[Array[U8] iso] tag = this
        fun ref apply () => _stream.close()
      end
      let closeNotify': CloseNotify tag = closeNotify
      pipeNotifiers'.push(closeNotify')
      stream.subscribe(consume closeNotify)

      _pipeNotifiers' = consume pipeNotifiers'
      stream.piped(this)
      _isPiped = true
      notifyPipe()
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
    _pipeNotifiers' = None

  fun ref _close() =>
    if not destroyed() then
       @quic_stream_close_stream(_stream)
      _isDestroyed = true
      notifyClose()
      let subscribers': Subscribers = subscribers()
      subscribers'.clear()
      _pipeNotifiers' = None
      _isPiped = false
    end

  be close() =>
    if _readable and _writeable then
      try
        @quic_stream_shutdown(_stream, ShutdownAbort())?
        _writeable = false
        _readable = false
      else
        notifyError(Exception("Stream failed to shutdown"))
      end
      _close()
    elseif not _readable and _writeable then
      try
        @quic_stream_shutdown(_stream, ShutdownGraceful())?
        _writeable = false
      else
        notifyError(Exception("Stream failed to close write path"))
      end
      _close()
    elseif _readable and not _writeable then
      try
        @quic_stream_shutdown(_stream, ShutdownAbortReceive())?
        _readable = false
      else
        notifyError(Exception("Stream failed to close read path"))
      end
      _close()
    end

  be closeRead() =>
    try
      @quic_stream_shutdown(_stream, ShutdownAbortReceive())?
      _readable = false
    else
      notifyError(Exception("Stream failed to close read path"))
    end

  be closeWrite() =>
    try
      @quic_stream_shutdown(_stream, ShutdownGraceful())?
      _writeable = false
    else
      notifyError(Exception("Stream failed to close write path"))
    end
