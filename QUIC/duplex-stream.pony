use "Streams"
use "Exception"
use "collections"
use @quic_get_stream_event_type_as_uint[U8](event: Pointer[None] tag)
use @quic_stream_get_total_buffer_length[U64](event: Pointer[None] tag)
use @quic_stream_status_pending[U32]()
use @pony_alloc[Pointer[U8]](ctx: Pointer[None], size: USize)
use @pony_ctx[Pointer[None]]()
use @quic_stream_get_total_buffer[None](event: Pointer[None] tag, buffer: Pointer[U8] tag, stream: Pointer[None] tag)
type QUICStream (QUICDuplexStream | QUICReadableStream | QUICWriteableStream)


primitive _QUICStreamCallback(strm: Pointer[None] tag, context: Pointer[None] tag, event: Pointer[None] tag, stream: QUICStream) : U32 =>
  match @quic_get_stream_event_type_as_uint(event)
    //QUIC_STREAM_EVENT_START_COMPLETE
    | 0 =>
    //QUIC_STREAM_EVENT_RECEIVE
    | 1 =>
      match stream
        | let stream': QUICDuplexStream =>
          stream'._receive(event)
          return @quic_stream_status_pending()
        | let stream': QUICReadableStream =>
          stream'._receive(event)
          return @quic_stream_status_pending()
        else
          return 1
      end
    //QUIC_STREAM_EVENT_SEND_COMPLETE
    | 2 =>
    //QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN
      match stream
        | let stream': QUICDuplexStream =>
          stream.closeWrite()
          return @quic_stream_status_pending()
        | let stream': QUICReadableStream =>
          stream'._receive(event)
          return @quic_stream_status_pending()
        else
          return 1
      end
    | 3 =>
    //QUIC_STREAM_EVENT_PEER_SEND_ABORTED
    | 4 =>
    //QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED
    | 5 =>
    //QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE
    | 6 =>
    //QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE
    | 7 =>
    //QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE
    | 8 =>
    //QUIC_STREAM_EVENT_PEER_ACCEPTED
    | 9 =>
  end
  return 0

actor QUICDuplexStream is DuplexPushStream[Array[U8] iso]
  var _readable: Bool = true
  var _writeable: Bool = true
  var _isDestroyed: Bool = false
  let _subscribers': Subscribers
  var _pipeNotifiers': (Array[Notify tag] iso | None) = None
  var _isPiped: Bool = false
  let _stream: Pointer[None] tag
  let _buffer: RingBuffer[U8]

  new create(stream = Pointer[None] tag) =>
    _subscribers' = Subscribers(3)
    _buffer: RingBuffer(128000)

  fun ref subscribers(): Subscribers=>
    _subscribers'

  fun destroyed(): Bool =>
    _isDestroyed

  fun readable(): Bool =>
    _readable

  be _receive(event: Pointer[None] tag) =>
    let data Array[U8] iso = recover
      let size: U64 = @quic_stream_get_total_buffer_length(event)
      let buffer: Pointer[U8] = @pony_alloc(@pony_ctx(), size.usize())
      @quic_stream_get_total_buffer(event, buffer, stream)
      let data' = Array.cpointer(buffer, size)
      data'
    end
    notifyData(consume data)


  be push() =>
    if destroyed() then
      notifyError(Exception("Stream has been destroyed"))
    else
      /*
      notifyData(consume chunk)
      if (_file.size() == _file.position()) then
        notifyComplete()
        closeRead()
      else
        push()
      end*/
    end

  be write(data: Array[U8] iso) =>
    if destroyed() then
      notifyError(Exception("Stream has been destroyed"))
    else
    end

  be read(cb: {(Array[U8] iso)} val, size: (USize | None) = None) =>
    if destroyed() then
      notifyError(Exception("Stream has been destroyed"))
    else
      var size' = match size
      | None => _buffer.size()
      | let size'': USize => size''
      end
      size' = size'.min(_buffer.size())

      let data = recover Array[U8](size') end
      let stop = _buffer.head() + size'
      try
        for i in Range(_buffer.head(), stop) do
          data.push(_buffer(i)?)
        end
        cb(consume data)
        try
          if stop < _buffer.size() then
            let buf = Array[U8](_buffer.size() - stop)
            for i in Range(stop, _buffer.size()) do
              buf.push(_buffer(i)?)
            end
            _buffer.clear()
            for i in buf.values() do
              _buffer.push(i)
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
      _isDestroyed = true
      notifyClose()
      let subscribers': Subscribers = subscribers()
      subscribers'.clear()
      _pipeNotifiers' = None
      _isPiped = false
    end

  be close() =>
    _close()

  be closeRead() =>
    _close()

  be closeWrite() =>
    _close()

  fun ref notifyData(data: Array[U8] iso) =>
    try
      let subscribers': Subscribers  = subscribers()
      var notify'': (DataNotify[Array[U8] iso] | None) =  None
      let onces = Array[USize](subscribers'.size())

      var i: USize = 0
      for notify in subscribers'(DataKey[Array[U8] iso])?.values() do
        match notify
        |  (let notify': DataNotify[Array[U8] iso], let once: Bool) =>
            notify'' = notify'
            if once then
              onces.push(i)
            end
            break
        end
        i = i + 1
      end

      match notify''
        | let notify''': DataNotify[R] =>
          if _buffer.size() > 0 then
            try
              data' = recover Array[U8](_buffer.size() + data.size()) end
              for i in Range(_buffer.head(), _buffer.head() + _buffer.size()) do
                data'.push(_buffer(i)?)
              end
              for i in data.values() do
                data'.push(i)
              end
              notify'''(consume data')
              _buffer.clear()
            else
              notifyError(Exception("Error copying buffer"))
            end
          else
            notify'''(consume data)
          end
        else
          let overflow = for i in data.values() do
            _buffer.push(i)
          end
          if overflow then
            _notifyOverflow()
          end
      end
      if onces.size() > 0 then
        discardOnces(subscribers'(DataKey[R])?, onces)
      end
    end
