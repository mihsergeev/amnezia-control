"""Accept only bounded, static PNGs from the panel's logo editor."""

import struct
import zlib


MAX_PNG_BYTES = 360 * 1024
MAX_PNG_SIDE = 288
_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def normalize_png(image: bytes) -> bytes:
    """Validate a canvas PNG and discard all ancillary data before storage."""
    error = ValueError("Invalid logo PNG")
    if not image.startswith(_SIGNATURE) or len(image) > MAX_PNG_BYTES:
        raise error
    offset = len(_SIGNATURE)
    header = None
    idat = bytearray()
    idat_seen = False
    idat_closed = False
    complete = False
    while offset + 12 <= len(image):
        size, kind = struct.unpack_from(">I4s", image, offset)
        end = offset + 8 + size
        if end + 4 > len(image):
            raise error
        data = image[offset + 8 : end]
        checksum = struct.unpack_from(">I", image, end)[0]
        if zlib.crc32(data, zlib.crc32(kind)) != checksum:
            raise error
        offset = end + 4
        if header is None:
            if kind != b"IHDR" or size != 13:
                raise error
            width, height, depth, color, compression, filtering, interlace = struct.unpack(
                ">IIBBBBB", data
            )
            channels = {0: 1, 2: 3, 4: 2, 6: 4}.get(color)
            if (
                not 1 <= width <= MAX_PNG_SIDE
                or not 1 <= height <= MAX_PNG_SIDE
                or depth != 8
                or channels is None
                or compression
                or filtering
                or interlace
            ):
                raise error
            row_size = 1 + width * channels
            header = data
        elif kind == b"IDAT":
            if idat_closed:
                raise error
            idat_seen = True
            idat.extend(data)
        elif kind == b"IEND":
            complete = size == 0 and offset == len(image)
            break
        elif not kind.isalpha() or not kind[:1].islower() or kind[2:3].islower():
            # The editor emits direct-color PNGs; unknown critical chunks,
            # including palettes, must never survive normalization.
            raise error
        elif idat_seen:
            idat_closed = True

    if header is None or not idat or not complete:
        raise error
    try:
        inflater = zlib.decompressobj()
        size = height * row_size
        raw = inflater.decompress(idat, size + 1)
    except zlib.error as exc:
        raise error from exc
    if (
        len(raw) != size
        or not inflater.eof
        or inflater.unused_data
        or inflater.unconsumed_tail
        or any(filter_type > 4 for filter_type in raw[::row_size])
    ):
        raise error

    return (
        _SIGNATURE + _chunk(b"IHDR", header) + _chunk(b"IDAT", bytes(idat)) + _chunk(b"IEND", b"")
    )
