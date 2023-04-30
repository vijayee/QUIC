use "Streams"
use "Exception"
use "collections"

actor QUICReadableStream is ReadablePushStream[Array[U8] iso]
  var _readable: Bool = true
  var _isDestroyed: Bool = false
  let _subscribers': Subscribers
  var _pipeNotifiers': (Array[Notify tag] iso | None) = None
  var _isPiped: Bool = false
  var _auto: Bool = false
  let _ctx: Pointer[None] tag
  let _stream: Pointer[None] tag
  let _buffer: RingBuffer[U8]

  new _create(stream: Pointer[None] tag, ctx: Pointer[None] tag) =>
    _subscribers' = Subscribers(3)
    _ctx = ctx
    _stream = stream
    _buffer = RingBuffer[U8](128000)

  fun _final() =>
    @quic_free(_ctx)
    @quic_stream_close_stream(_stream)

  fun readable(): Bool =>
    _readable

  fun destroyed(): Bool =>
    _isDestroyed

  fun ref isPiped(): Bool =>
    _isPiped

  fun ref pipeNotifiers(): (Array[Notify tag] iso^ | None) =>
    _pipeNotifiers' = None

  fun ref autoPush(): Bool =>
    _auto

  fun ref subscribers() : Subscribers =>
    _subscribers'

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

  be _dispatchPeerReceiveAborted(data: PeerReceiveAbortedData) =>
    notifyPayload[PeerReceiveAbortedData](PeerReceiveAbortedEvent, data)

  be _dispatchPeerSendShutdown() =>
    _readable = false
    _shutdown()
    notify(PeerSendShutdownEvent)

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

  be pipe(stream: WriteablePushStream[Array[U8] iso] tag) =>
    if destroyed() then
      notifyError(Exception("Stream has been destroyed"))
    else
      let pipeNotifiers': Array[Notify tag] iso = try
         pipeNotifiers() as Array[Notify tag] iso^
      else
        let pipeNotifiers' = recover Array[Notify tag] end
        consume pipeNotifiers'
      end

      let pipedNotify: PipedNotify iso =  object iso is PipedNotify
        let _stream: ReadablePushStream[Array[U8] iso] tag = this
        fun ref apply() =>
          _stream.push()
      end
      let pipedNotify': PipedNotify tag = pipedNotify
      pipeNotifiers'.push(pipedNotify')
      stream.subscribe(consume pipedNotify)

      let errorNotify: ErrorNotify iso = object iso  is ErrorNotify
        let _stream: ReadablePushStream[Array[U8] iso] tag = this
        fun ref apply (ex: Exception) => _stream.destroy(ex)
      end
      let errorNotify': ErrorNotify tag = errorNotify
      pipeNotifiers'.push(errorNotify')
      stream.subscribe(consume errorNotify)

      let closeNotify: CloseNotify iso = object iso  is CloseNotify
        let _stream: ReadablePushStream[Array[U8] iso] tag = this
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
