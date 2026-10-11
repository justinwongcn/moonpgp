///|
/// Compression algorithms for the Compressed Data packet
/// (RFC 9580 §9.4).
pub(all) enum CompressedAlgo {
  Uncompressed
  Zip
  Zlib
  BZip2
} derive(Eq, Debug)

///|
pub fn CompressedAlgo::number(self : CompressedAlgo) -> Int {
  match self {
    Uncompressed => 0
    Zip => 1
    Zlib => 2
    BZip2 => 3
  }
}

///|
pub fn compressed_algo_of_number(n : Int) -> CompressedAlgo? {
  match n {
    0 => Some(Uncompressed)
    1 => Some(Zip)
    2 => Some(Zlib)
    3 => Some(BZip2)
    _ => None
  }
}

///|
/// Raw DEFLATE (RFC 1951) — the ZIP algorithm of the Compressed packet.
pub fn zip_compress(data : BytesView) -> Bytes {
  @flate.deflate_all(data.to_owned())
}

///|
/// Raw DEFLATE decompression. The decompression end must be complete:
/// incoming mail may arrive compressed with dynamic Huffman tables.
pub fn zip_decompress(data : BytesView) -> Bytes raise {
  @flate.inflate_all(data.to_owned()) catch {
    _ => @error.fail("compress: inflate failed")
  }
}

///|
/// ZLIB (RFC 1950) wrapper — algorithm 2 of the Compressed packet.
pub fn zlib_compress(data : BytesView) -> Bytes {
  @zlib.zlib_compress(data.to_owned())
}

///|
pub fn zlib_decompress(data : BytesView) -> Bytes raise {
  @zlib.zlib_decompress(data.to_owned()) catch {
    _ => @error.fail("compress: zlib inflate failed")
  }
}

///|
pub extend CompressedAlgo with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend CompressedAlgo with Eq::{not_equal, equal}

///|
/// Raw DEFLATE decompression with a hard output cap (M4): flate's
/// limited inflater stops (raising) once the cap is exceeded, so the
/// bomb never materializes.
pub fn zip_decompress_capped(data : BytesView, max_out : Int) -> Bytes raise {
  @flate.inflate_all_limited(data.to_owned(), max_output=max_out) catch {
    _ => @error.fail("compress: inflate failed (limit \{max_out} octets)")
  }
}

///|
/// ZLIB decompression with a hard output cap (M4): the streaming decoder
/// runs with bounded output windows, so total allocation stays at the cap
/// instead of materializing the payload first. Checksum and framing stay
/// with the decoder.
pub fn zlib_decompress_capped(data : BytesView, max_out : Int) -> Bytes raise {
  guard max_out >= 0 else { @error.fail("compress: bad output cap") }
  let dec = @zlib.Decoder::Decoder()
  let out : Array[Byte] = []
  let mut pos = 0
  for ;; {
    let chunk = FixedArray::make(32768, b'\x00')
    let status = dec.step(
      data.exact_view()[pos:data.length()],
      chunk.mut_view(),
      end=true,
    ) catch {
      ZlibError(_, msg) => @error.fail("compress: zlib inflate failed: \{msg}")
    }
    pos = pos + dec.last_consumed()
    let produced = dec.last_produced()
    if out.length() + produced > max_out {
      @error.fail(
        "compress: decompressed output exceeds the \{max_out}-octet limit",
      )
    }
    for i in 0..<produced {
      out.push(chunk[i])
    }
    match status {
      Done => return Bytes::from_array(out)
      NeedMoreInput => @error.fail("compress: truncated zlib stream")
      NeedMoreOutput => continue
    }
  }
}
