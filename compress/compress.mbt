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
