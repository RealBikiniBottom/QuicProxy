//! Minimal QPACK (RFC 9204) subset used by the Hysteria2 HTTP/3 auth
//! handshake, plus the HPACK (RFC 7541 Appendix B) Huffman decoding it
//! needs.
//!
//! Only the features required to talk to real Hysteria2 servers are
//! implemented:
//! - Encoding: field sections built from literal-with-literal-name field
//!   lines, no dynamic table, no Huffman. This is what quic-go's QPACK
//!   decoder accepts for the request direction.
//! - Decoding: field sections using static-table references only
//!   (indexed field line, literal with static name reference, literal with
//!   literal name), optionally Huffman-encoded strings. Servers keep the
//!   dynamic table at capacity zero unless the client advertises
//!   SETTINGS_QPACK_MAX_TABLE_CAPACITY, which this client does not.

use anyhow::{Context, Result, bail};

/// HPACK (RFC 7541 Appendix B) Huffman table: `(code, bit length)` per
/// symbol. Row 256 is EOS.
const HPACK_HUFFMAN: [(u32, u8); 257] = [
    (0x00001ff8, 13), // 0
    (0x007fffd8, 23), // 1
    (0x0fffffe2, 28), // 2
    (0x0fffffe3, 28), // 3
    (0x0fffffe4, 28), // 4
    (0x0fffffe5, 28), // 5
    (0x0fffffe6, 28), // 6
    (0x0fffffe7, 28), // 7
    (0x0fffffe8, 28), // 8
    (0x00ffffea, 24), // 9
    (0x3ffffffc, 30), // 10
    (0x0fffffe9, 28), // 11
    (0x0fffffea, 28), // 12
    (0x3ffffffd, 30), // 13
    (0x0fffffeb, 28), // 14
    (0x0fffffec, 28), // 15
    (0x0fffffed, 28), // 16
    (0x0fffffee, 28), // 17
    (0x0fffffef, 28), // 18
    (0x0ffffff0, 28), // 19
    (0x0ffffff1, 28), // 20
    (0x0ffffff2, 28), // 21
    (0x3ffffffe, 30), // 22
    (0x0ffffff3, 28), // 23
    (0x0ffffff4, 28), // 24
    (0x0ffffff5, 28), // 25
    (0x0ffffff6, 28), // 26
    (0x0ffffff7, 28), // 27
    (0x0ffffff8, 28), // 28
    (0x0ffffff9, 28), // 29
    (0x0ffffffa, 28), // 30
    (0x0ffffffb, 28), // 31
    (0x00000014, 6), // 32
    (0x000003f8, 10), // 33
    (0x000003f9, 10), // 34
    (0x00000ffa, 12), // 35
    (0x00001ff9, 13), // 36
    (0x00000015, 6), // 37
    (0x000000f8, 8), // 38
    (0x000007fa, 11), // 39
    (0x000003fa, 10), // 40
    (0x000003fb, 10), // 41
    (0x000000f9, 8), // 42
    (0x000007fb, 11), // 43
    (0x000000fa, 8), // 44
    (0x00000016, 6), // 45
    (0x00000017, 6), // 46
    (0x00000018, 6), // 47
    (0x00000000, 5), // 48
    (0x00000001, 5), // 49
    (0x00000002, 5), // 50
    (0x00000019, 6), // 51
    (0x0000001a, 6), // 52
    (0x0000001b, 6), // 53
    (0x0000001c, 6), // 54
    (0x0000001d, 6), // 55
    (0x0000001e, 6), // 56
    (0x0000001f, 6), // 57
    (0x0000005c, 7), // 58
    (0x000000fb, 8), // 59
    (0x00007ffc, 15), // 60
    (0x00000020, 6), // 61
    (0x00000ffb, 12), // 62
    (0x000003fc, 10), // 63
    (0x00001ffa, 13), // 64
    (0x00000021, 6), // 65
    (0x0000005d, 7), // 66
    (0x0000005e, 7), // 67
    (0x0000005f, 7), // 68
    (0x00000060, 7), // 69
    (0x00000061, 7), // 70
    (0x00000062, 7), // 71
    (0x00000063, 7), // 72
    (0x00000064, 7), // 73
    (0x00000065, 7), // 74
    (0x00000066, 7), // 75
    (0x00000067, 7), // 76
    (0x00000068, 7), // 77
    (0x00000069, 7), // 78
    (0x0000006a, 7), // 79
    (0x0000006b, 7), // 80
    (0x0000006c, 7), // 81
    (0x0000006d, 7), // 82
    (0x0000006e, 7), // 83
    (0x0000006f, 7), // 84
    (0x00000070, 7), // 85
    (0x00000071, 7), // 86
    (0x00000072, 7), // 87
    (0x000000fc, 8), // 88
    (0x00000073, 7), // 89
    (0x000000fd, 8), // 90
    (0x00001ffb, 13), // 91
    (0x0007fff0, 19), // 92
    (0x00001ffc, 13), // 93
    (0x00003ffc, 14), // 94
    (0x00000022, 6), // 95
    (0x00007ffd, 15), // 96
    (0x00000003, 5), // 97
    (0x00000023, 6), // 98
    (0x00000004, 5), // 99
    (0x00000024, 6), // 100
    (0x00000005, 5), // 101
    (0x00000025, 6), // 102
    (0x00000026, 6), // 103
    (0x00000027, 6), // 104
    (0x00000006, 5), // 105
    (0x00000074, 7), // 106
    (0x00000075, 7), // 107
    (0x00000028, 6), // 108
    (0x00000029, 6), // 109
    (0x0000002a, 6), // 110
    (0x00000007, 5), // 111
    (0x0000002b, 6), // 112
    (0x00000076, 7), // 113
    (0x0000002c, 6), // 114
    (0x00000008, 5), // 115
    (0x00000009, 5), // 116
    (0x0000002d, 6), // 117
    (0x00000077, 7), // 118
    (0x00000078, 7), // 119
    (0x00000079, 7), // 120
    (0x0000007a, 7), // 121
    (0x0000007b, 7), // 122
    (0x00007ffe, 15), // 123
    (0x000007fc, 11), // 124
    (0x00003ffd, 14), // 125
    (0x00001ffd, 13), // 126
    (0x0ffffffc, 28), // 127
    (0x000fffe6, 20), // 128
    (0x003fffd2, 22), // 129
    (0x000fffe7, 20), // 130
    (0x000fffe8, 20), // 131
    (0x003fffd3, 22), // 132
    (0x003fffd4, 22), // 133
    (0x003fffd5, 22), // 134
    (0x007fffd9, 23), // 135
    (0x003fffd6, 22), // 136
    (0x007fffda, 23), // 137
    (0x007fffdb, 23), // 138
    (0x007fffdc, 23), // 139
    (0x007fffdd, 23), // 140
    (0x007fffde, 23), // 141
    (0x00ffffeb, 24), // 142
    (0x007fffdf, 23), // 143
    (0x00ffffec, 24), // 144
    (0x00ffffed, 24), // 145
    (0x003fffd7, 22), // 146
    (0x007fffe0, 23), // 147
    (0x00ffffee, 24), // 148
    (0x007fffe1, 23), // 149
    (0x007fffe2, 23), // 150
    (0x007fffe3, 23), // 151
    (0x007fffe4, 23), // 152
    (0x001fffdc, 21), // 153
    (0x003fffd8, 22), // 154
    (0x007fffe5, 23), // 155
    (0x003fffd9, 22), // 156
    (0x007fffe6, 23), // 157
    (0x007fffe7, 23), // 158
    (0x00ffffef, 24), // 159
    (0x003fffda, 22), // 160
    (0x001fffdd, 21), // 161
    (0x000fffe9, 20), // 162
    (0x003fffdb, 22), // 163
    (0x003fffdc, 22), // 164
    (0x007fffe8, 23), // 165
    (0x007fffe9, 23), // 166
    (0x001fffde, 21), // 167
    (0x007fffea, 23), // 168
    (0x003fffdd, 22), // 169
    (0x003fffde, 22), // 170
    (0x00fffff0, 24), // 171
    (0x001fffdf, 21), // 172
    (0x003fffdf, 22), // 173
    (0x007fffeb, 23), // 174
    (0x007fffec, 23), // 175
    (0x001fffe0, 21), // 176
    (0x001fffe1, 21), // 177
    (0x003fffe0, 22), // 178
    (0x001fffe2, 21), // 179
    (0x007fffed, 23), // 180
    (0x003fffe1, 22), // 181
    (0x007fffee, 23), // 182
    (0x007fffef, 23), // 183
    (0x000fffea, 20), // 184
    (0x003fffe2, 22), // 185
    (0x003fffe3, 22), // 186
    (0x003fffe4, 22), // 187
    (0x007ffff0, 23), // 188
    (0x003fffe5, 22), // 189
    (0x003fffe6, 22), // 190
    (0x007ffff1, 23), // 191
    (0x03ffffe0, 26), // 192
    (0x03ffffe1, 26), // 193
    (0x000fffeb, 20), // 194
    (0x0007fff1, 19), // 195
    (0x003fffe7, 22), // 196
    (0x007ffff2, 23), // 197
    (0x003fffe8, 22), // 198
    (0x01ffffec, 25), // 199
    (0x03ffffe2, 26), // 200
    (0x03ffffe3, 26), // 201
    (0x03ffffe4, 26), // 202
    (0x07ffffde, 27), // 203
    (0x07ffffdf, 27), // 204
    (0x03ffffe5, 26), // 205
    (0x00fffff1, 24), // 206
    (0x01ffffed, 25), // 207
    (0x0007fff2, 19), // 208
    (0x001fffe3, 21), // 209
    (0x03ffffe6, 26), // 210
    (0x07ffffe0, 27), // 211
    (0x07ffffe1, 27), // 212
    (0x03ffffe7, 26), // 213
    (0x07ffffe2, 27), // 214
    (0x00fffff2, 24), // 215
    (0x001fffe4, 21), // 216
    (0x001fffe5, 21), // 217
    (0x03ffffe8, 26), // 218
    (0x03ffffe9, 26), // 219
    (0x0ffffffd, 28), // 220
    (0x07ffffe3, 27), // 221
    (0x07ffffe4, 27), // 222
    (0x07ffffe5, 27), // 223
    (0x000fffec, 20), // 224
    (0x00fffff3, 24), // 225
    (0x000fffed, 20), // 226
    (0x001fffe6, 21), // 227
    (0x003fffe9, 22), // 228
    (0x001fffe7, 21), // 229
    (0x001fffe8, 21), // 230
    (0x007ffff3, 23), // 231
    (0x003fffea, 22), // 232
    (0x003fffeb, 22), // 233
    (0x01ffffee, 25), // 234
    (0x01ffffef, 25), // 235
    (0x00fffff4, 24), // 236
    (0x00fffff5, 24), // 237
    (0x03ffffea, 26), // 238
    (0x007ffff4, 23), // 239
    (0x03ffffeb, 26), // 240
    (0x07ffffe6, 27), // 241
    (0x03ffffec, 26), // 242
    (0x03ffffed, 26), // 243
    (0x07ffffe7, 27), // 244
    (0x07ffffe8, 27), // 245
    (0x07ffffe9, 27), // 246
    (0x07ffffea, 27), // 247
    (0x07ffffeb, 27), // 248
    (0x0ffffffe, 28), // 249
    (0x07ffffec, 27), // 250
    (0x07ffffed, 27), // 251
    (0x07ffffee, 27), // 252
    (0x07ffffef, 27), // 253
    (0x07fffff0, 27), // 254
    (0x03ffffee, 26), // 255
    (0x3fffffff, 30), // 256
];

/// QPACK static table (RFC 9204 Appendix A): `(name, value)`, row = index.
pub(crate) const QPACK_STATIC_TABLE: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    ("strict-transport-security", "max-age=31536000; includesubdomains"),
    ("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

/// Append a prefixed integer (RFC 9204 section 4.1.1) to `out`.
///
/// `flags` are pre-ORed into the first byte's high bits; the integer
/// occupies its low `prefix` bits.
fn append_int(out: &mut Vec<u8>, prefix: u8, value: u64, flags: u8) {
    let max = (1u64 << prefix) - 1;
    if value < max {
        out.push(flags | value as u8);
        return;
    }
    out.push(flags | max as u8);
    let mut rest = value - max;
    while rest >= 128 {
        out.push((rest as u8 & 0x7f) | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}

/// Cursor over a byte slice used by the QPACK decoder.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn read_byte(&mut self) -> Result<u8> {
        let b = *self
            .buf
            .get(self.pos)
            .context("truncated QPACK field section")?;
        self.pos += 1;
        Ok(b)
    }

    /// Read a prefixed integer starting at the current byte.
    fn read_int(&mut self, prefix: u8) -> Result<u64> {
        let max = (1u64 << prefix) - 1;
        let first = self.read_byte()?;
        let mut value = (first as u64) & max;
        if value < max {
            return Ok(value);
        }
        let mut shift = 0u32;
        loop {
            let byte = self.read_byte()?;
            value += ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
            if shift > 63 {
                bail!("QPACK integer overflow");
            }
        }
    }

    /// Read a string literal with an N-bit prefix (RFC 9204 section 4.1.2).
    ///
    /// The literal's Huffman flag sits immediately before a `(N-1)`-bit
    /// length prefix. `N` is the total prefix width: 8 for a string
    /// starting on a byte boundary, 4 for a field name inside a
    /// literal-with-literal-name field line.
    fn read_string(&mut self, prefix_width: u8) -> Result<Vec<u8>> {
        let first = self.read_byte()?;
        let huffman = match prefix_width {
            4 => first & 0x08 != 0,
            8 => first & 0x80 != 0,
            _ => unreachable!("unsupported string prefix width"),
        };
        // Re-read the length: the Huffman flag was bit (prefix_width - 1),
        // the length starts at bit (prefix_width - 2).
        let length_prefix = prefix_width - 1;
        let mask = (1u8 << length_prefix) - 1;
        let mut length = (first & mask) as u64;
        if length >= (1u64 << length_prefix) - 1 {
            let mut shift = 0u32;
            loop {
                let byte = self.read_byte()?;
                length += ((byte & 0x7f) as u64) << shift;
                if byte & 0x80 == 0 {
                    break;
                }
                shift += 7;
                if shift > 63 {
                    bail!("QPACK string length overflow");
                }
            }
        }
        let length = usize::try_from(length).context("QPACK string too long")?;
        if self.remaining() < length {
            bail!("truncated QPACK string");
        }
        let raw = &self.buf[self.pos..self.pos + length];
        self.pos += length;
        if huffman {
            huffman_decode(raw)
        } else {
            Ok(raw.to_vec())
        }
    }
}

/// Decode an HPACK (RFC 7541 Appendix B) Huffman-coded byte string.
///
/// Codes are read most-significant bit first; a code matches when its
/// length equals the number of bits consumed so far and its value equals
/// the accumulated bits. Trailing padding must be a prefix of EOS.
fn huffman_decode(input: &[u8]) -> Result<Vec<u8>> {
    let total_bits = input.len() * 8;
    let mut out = Vec::with_capacity(input.len());
    let mut acc: u32 = 0;
    let mut acc_len: u8 = 0;
    let mut stream_pos = 0usize;

    while stream_pos < total_bits {
        let bit = (input[stream_pos / 8] >> (7 - stream_pos % 8)) & 1;
        stream_pos += 1;
        acc = (acc << 1) | bit as u32;
        acc_len += 1;

        let mut matched = None;
        for (sym, &(code, len)) in HPACK_HUFFMAN.iter().enumerate() {
            if len == acc_len && code == acc {
                matched = Some(sym);
                break;
            }
        }
        match matched {
            Some(256) => bail!("Huffman EOS symbol in string"),
            Some(sym) => {
                out.push(sym as u8);
                acc = 0;
                acc_len = 0;
            }
            None => {
                if acc_len == 30 {
                    bail!("invalid Huffman code");
                }
            }
        }
    }

    // Trailing bits of the final byte are padding and must be all ones
    // (the EOS code is 30 one bits, so ones are a valid prefix of it).
    let padded = total_bits - stream_pos;
    if padded > 0 {
        let mask = (1u8 << padded) - 1;
        if input[input.len() - 1] & mask != mask {
            bail!("invalid Huffman padding");
        }
    }
    Ok(out)
}

/// Encode a request header field section: required-insert-count 0,
/// base 0, then literal-with-literal-name field lines (no Huffman, no
/// dynamic table).
pub(crate) fn encode_field_section(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x00); // Required Insert Count = 0
    out.push(0x00); // Base = 0 (sign 0, delta 0)
    for (name, value) in fields {
        append_int(&mut out, 3, name.len() as u64, 0x20); // 001 + N=0, H=0
        out.extend_from_slice(name.as_bytes());
        append_int(&mut out, 7, value.len() as u64, 0x00); // H=0
        out.extend_from_slice(value.as_bytes());
    }
    out
}

/// Decode a response header field section into `(name, value)` pairs.
pub(crate) fn decode_field_section(block: &[u8]) -> Result<Vec<(String, String)>> {
    let mut rd = Reader::new(block);
    let required_insert_count = rd.read_int(8)?;
    if required_insert_count != 0 {
        // Servers never use the dynamic table against this client (it
        // advertises zero capacity), so a nonzero insert count means the
        // stream is not decodable here.
        bail!("QPACK field section references the dynamic table");
    }
    let base = rd.read_int(7)?;
    if base != 0 {
        bail!("QPACK field section has a nonzero base");
    }

    let mut fields = Vec::new();
    while rd.remaining() > 0 {
        let first = rd.buf[rd.pos];
        if first & 0x80 != 0 {
            // Indexed field line (static, since T bit must be 1).
            if first & 0x40 == 0 {
                bail!("QPACK indexed field line with dynamic reference");
            }
            let index = rd.read_int(6)?;
            let (name, value) = QPACK_STATIC_TABLE
                .get(index as usize)
                .with_context(|| format!("QPACK static index {index} out of range"))?;
            fields.push(((*name).to_string(), (*value).to_string()));
        } else if first & 0xc0 == 0x40 {
            // Literal field line with name reference.
            let index = rd.read_int(4)?;
            let (name, _) = QPACK_STATIC_TABLE
                .get(index as usize)
                .with_context(|| format!("QPACK static name index {index} out of range"))?;
            let value = rd.read_string(8)?;
            fields.push(((name).to_string(), String::from_utf8_lossy(&value).into_owned()));
        } else if first & 0xe0 == 0x20 {
            // Literal field line with literal name.
            let name = rd.read_string(4)?;
            let value = rd.read_string(8)?;
            fields.push((
                String::from_utf8_lossy(&name).into_owned(),
                String::from_utf8_lossy(&value).into_owned(),
            ));
        } else {
            bail!("unsupported QPACK field line type byte: {first:#x}");
        }
    }
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixed_integer_roundtrip_across_prefix_sizes() {
        for prefix in 1..=8u8 {
            for value in [0u64, 1, 3, 14, 15, 16, 127, 128, 255, 256, 16384, 2u64.pow(20)] {
                let mut buf = Vec::new();
                append_int(&mut buf, prefix, value, 0);
                let mut rd = Reader::new(&buf);
                assert_eq!(rd.read_int(prefix).unwrap(), value, "prefix {prefix} value {value}");
                assert_eq!(rd.remaining(), 0);
            }
        }
    }

    #[test]
    fn flags_survive_prefixed_integer_encoding() {
        let mut buf = Vec::new();
        append_int(&mut buf, 4, 24, 0x50); // literal-with-name-ref :status pattern
        assert_eq!(buf[0] & 0xf0, 0x50);
        let mut rd = Reader::new(&buf);
        assert_eq!(rd.read_int(4).unwrap(), 24);
    }

    #[test]
    fn huffman_decodes_rfc7541_example() {
        // RFC 7541 C.4.1: "www.example.com" Huffman-coded.
        let encoded = hex::decode("f1e3c2e5f23a6ba0ab90f4ff").unwrap();
        assert_eq!(huffman_decode(&encoded).unwrap(), b"www.example.com");
    }

    #[test]
    fn huffman_table_spot_checks() {
        // 'a' -> code 0x03, len 5 (RFC 7541 Appendix B).
        let (code, len) = HPACK_HUFFMAN[97];
        assert_eq!(len, 5);
        assert_eq!(code, 0x03);
        let (_, len) = HPACK_HUFFMAN[233];
        assert_eq!(len, 22);
    }

    #[test]
    fn field_section_roundtrip() {
        let fields = [
            (":method", "POST"),
            (":scheme", "https"),
            (":path", "/auth"),
            (":authority", "hysteria"),
            ("hysteria-auth", "secret-password"),
            ("hysteria-cc-rx", "0"),
            ("hysteria-padding", "0123456789"),
        ];
        let encoded = encode_field_section(&fields);
        // First bytes are the zero prefix.
        assert_eq!(&encoded[..2], &[0x00, 0x00]);
        let decoded = decode_field_section(&encoded).unwrap();
        let expected: Vec<(String, String)> = fields
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn decode_quic_go_style_status_233_response() {
        // What quic-go/qpack's encoder emits for
        //   :status: 233 / hysteria-udp: true
        // Reproduce it with a small local encoder mirroring quic-go's
        // writeLiteralFieldWithNameReference / writeLiteralFieldWithoutNameReference
        // (Huffman-enabled literals).
        fn huffman_encode(input: &str) -> Vec<u8> {
            // Straightforward MSB-first canonical encoder over the table.
            let mut out: Vec<u8> = Vec::new();
            let mut acc: u32 = 0;
            let mut bits: u8 = 0;
            for b in input.bytes() {
                let (code, len) = HPACK_HUFFMAN[b as usize];
                acc = (acc << len) | code;
                bits += len;
                while bits >= 8 {
                    bits -= 8;
                    out.push((acc >> bits) as u8);
                }
            }
            // EOS padding of all ones.
            if bits > 0 {
                let pad = 8 - bits;
                acc = (acc << pad) | ((1u32 << pad) - 1);
                out.push(acc as u8);
            }
            out
        }

        fn name_ref(buf: &mut Vec<u8>, index: u64, value: &str) {
            // 01 + N=0 + T=1, 4-bit index prefix.
            append_int(buf, 4, index, 0x50);
            // 8-bit-prefix string, Huffman on.
            let enc = huffman_encode(value);
            append_int(buf, 7, enc.len() as u64, 0x80);
            buf.extend_from_slice(&enc);
        }

        fn literal(buf: &mut Vec<u8>, name: &str, value: &str) {
            // 001 + N=0, then name as 4-bit-prefix string (H at bit 3),
            // then value as 8-bit-prefix string.
            let name_enc = huffman_encode(name);
            append_int(buf, 3, name_enc.len() as u64, 0x20 | 0x08);
            buf.extend_from_slice(&name_enc);
            let val_enc = huffman_encode(value);
            append_int(buf, 7, val_enc.len() as u64, 0x80);
            buf.extend_from_slice(&val_enc);
        }

        let mut block = vec![0x00, 0x00];
        name_ref(&mut block, 24, "233");
        literal(&mut block, "hysteria-udp", "true");
        literal(&mut block, "hysteria-cc-rx", "auto");
        literal(&mut block, "hysteria-padding", "abcdef");

        let fields = decode_field_section(&block).unwrap();
        assert_eq!(fields[0], (":status".to_string(), "233".to_string()));
        assert_eq!(fields[1], ("hysteria-udp".to_string(), "true".to_string()));
        assert_eq!(fields[2], ("hysteria-cc-rx".to_string(), "auto".to_string()));
    }

    #[test]
    fn decode_static_indexed_status() {
        // Indexed field line: 0xC0 | 25 == :status 200.
        let block = [0x00, 0x00, 0xc0 | 25];
        let fields = decode_field_section(&block).unwrap();
        assert_eq!(fields[0], (":status".to_string(), "200".to_string()));
    }
}
