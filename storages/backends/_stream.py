"""Small file-like helpers used by remote-storage streaming reads."""


def validate_byte_range(start, length):
    """Validate the half-open byte range accepted by `open_stream()`.

    A zero-length response should be handled by callers without opening an
    object. Requiring a positive length also avoids provider-specific behavior
    for invalid `Range` headers.
    """

    if start < 0:
        raise ValueError("start must be greater than or equal to zero")
    if length is not None and length <= 0:
        raise ValueError("length must be greater than zero")


class ChunkIteratorStream:
    """Expose an iterator of provider chunks through `read()`.

    Azure's download API provides an iterator rather than a file object. This
    wrapper retains at most one partially consumed provider chunk, so a caller
    can choose its own smaller read size without assembling the full object.
    """

    def __init__(self, chunks):
        self._chunks = iter(chunks)
        self._pending = b""

    def read(self, size=-1):
        """Read at most `size` bytes, or all remaining bytes when omitted."""

        if size is None:
            size = -1
        if size < 0:
            result = self._pending + b"".join(self._chunks)
            self._pending = b""
            return result

        while len(self._pending) < size:
            chunk = next(self._chunks, None)
            if chunk is None:
                break
            self._pending += chunk

        result, self._pending = self._pending[:size], self._pending[size:]
        return result


class LimitedStream:
    """Limit a file-like reader to the requested number of bytes."""

    def __init__(self, stream, length):
        self._stream = stream
        self._remaining = length

    def read(self, size=-1):
        """Read without crossing the range passed to `open_stream()`."""

        if self._remaining is None:
            return self._stream.read(size)
        if self._remaining == 0:
            return b""
        if size is None or size < 0 or size > self._remaining:
            size = self._remaining
        result = self._stream.read(size)
        self._remaining -= len(result)
        return result
