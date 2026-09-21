//! Shared plumbing for reading provider SSE streams as bytes, not wishes.
//!
//! ## Why this module exists
//!
//! Both streaming adapters (`openai` and `anthropic`) read the response body as a sequence of
//! arbitrary network chunks (`bytes_stream`). Two facts about those chunks make naive decoding
//! wrong, and both were paid for in corrupted streams before this module existed:
//!
//! 1. **A chunk is not a character.** TCP/HTTP splits the body at packet boundaries, which can
//!    fall in the middle of a multi-byte UTF-8 character (an emoji in the model's reply is the
//!    classic case). Converting each chunk independently with `String::from_utf8_lossy` replaces
//!    the split bytes with U+FFFD *twice* — once for the trailing half of one chunk, once for
//!    the leading half of the next — and the SSE JSON no longer parses, or worse, parses with
//!    a mojibake scar in the middle of the answer.
//! 2. **A chunk is not an event.** The SSE framing (`take_sse_event` / `take_sse_frame`) already
//!    buffers text until a blank line arrives; what it buffers must be the *faithful* text, so
//!    the byte-to-text step below it must be incremental too.
//!
//! [`Utf8StreamDecoder`] is the one place that turns bytes into text: raw bytes go in per chunk,
//! complete characters come out, and an incomplete trailing sequence is held back until the rest
//! of it arrives. Truly invalid bytes (not merely incomplete ones) still become U+FFFD rather
//! than failing the whole turn — a single bad byte must not cost an answer.

/// Incremental UTF-8 decoder over arbitrary network chunks.
///
/// Feed each `bytes_stream` item to [`Utf8StreamDecoder::push`]; it returns the newly completed
/// text. Bytes forming an incomplete character at the end of a chunk are retained internally and
/// prepended to the next chunk before decoding, so a character split across reads decodes cleanly
/// instead of becoming two replacement characters.
#[derive(Default, Debug)]
pub struct Utf8StreamDecoder {
    /// Bytes withheld from the last push: a trailing incomplete UTF-8 sequence.
    pending: Vec<u8>,
}

impl Utf8StreamDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode `chunk`, returning the text it completes.
    ///
    /// The returned string holds every complete character the buffered bytes now allow; any
    /// trailing incomplete sequence stays buffered for the next call. Invalid (as opposed to
    /// incomplete) bytes become U+FFFD, matching `from_utf8_lossy` for the bytes that are
    /// genuinely undecodable.
    pub fn push(&mut self, chunk: &[u8]) -> String {
        self.pending.extend_from_slice(chunk);
        let mut out = String::new();
        // Decode head-to-tail: emit every complete character, substitute genuinely invalid
        // bytes with U+FFFD, and stop at a trailing *incomplete* sequence, which stays
        // buffered for the next chunk.
        loop {
            if self.pending.is_empty() {
                break;
            }
            match std::str::from_utf8(&self.pending) {
                Ok(valid) => {
                    out.push_str(valid);
                    self.pending.clear();
                    break;
                }
                Err(err) => {
                    let upto = err.valid_up_to();
                    // `upto` is always a character boundary, so this never re-introduces a
                    // replacement character of its own.
                    out.push_str(&String::from_utf8_lossy(&self.pending[..upto]));
                    match err.error_len() {
                        // No length: the bytes from `upto` onward are a truncated character —
                        // hold them back and wait for the rest of them.
                        None => {
                            self.pending.drain(..upto);
                            break;
                        }
                        // A genuinely invalid byte span: substitute one U+FFFD, skip the
                        // offending bytes, and keep decoding what follows.
                        Some(len) => {
                            out.push('\u{FFFD}');
                            let skip = (upto + len).min(self.pending.len());
                            self.pending.drain(..skip);
                        }
                    }
                }
            }
        }
        out
    }

    /// Decode whatever is still buffered, replacing a trailing incomplete sequence.
    ///
    /// Called once at end-of-stream: if the vendor ended mid-character (it should not, but a
    /// truncated connection might), the dangling bytes become U+FFFD rather than vanishing.
    pub fn finish(&mut self) -> String {
        let rest = String::from_utf8_lossy(&self.pending).into_owned();
        self.pending.clear();
        rest
    }

    /// Whether bytes are still held back (only true mid-character between pushes).
    #[cfg(test)]
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stream_that_splits_a_multibyte_char_decodes_cleanly() {
        // The failure this decoder exists for: "héllo 🌍" split mid-`é` (2 bytes) and mid-`🌍`
        // (4 bytes). Per-chunk `from_utf8_lossy` would scar both with U+FFFD; the incremental
        // decoder holds the halves back and emits the characters whole.
        let text = "data: héllo 🌍\n\n";
        let bytes = text.as_bytes();
        // Split inside `é` (bytes 7..9) and inside `🌍`.
        let e_start = text.find('é').unwrap();
        let globe_start = text.find('🌍').unwrap();
        let cut1 = e_start + 1;
        let cut2 = globe_start + 2;

        let mut decoder = Utf8StreamDecoder::new();
        let mut out = String::new();
        out.push_str(&decoder.push(&bytes[..cut1]));
        assert!(decoder.has_pending(), "the half-é must be held back");
        assert!(!out.contains('�'), "no replacement char yet: {out:?}");
        out.push_str(&decoder.push(&bytes[cut1..cut2]));
        assert!(!out.contains('�'), "no replacement char yet: {out:?}");
        out.push_str(&decoder.push(&bytes[cut2..]));
        out.push_str(&decoder.finish());
        assert_eq!(out, text, "split characters decode whole");
    }

    #[test]
    fn complete_chunks_pass_through_unchanged() {
        let mut decoder = Utf8StreamDecoder::new();
        let out = decoder.push(b"data: {\"a\":1}\n\n");
        assert_eq!(out, "data: {\"a\":1}\n\n");
        assert_eq!(decoder.finish(), "");
    }

    #[test]
    fn a_truncated_tail_at_eof_becomes_a_replacement_char_rather_than_vanishing() {
        let mut decoder = Utf8StreamDecoder::new();
        let out = decoder.push(&[0xE2, 0x82]);
        assert_eq!(out, "", "incomplete sequence is held, not emitted");
        let tail = decoder.finish();
        assert!(tail.contains('�'), "dangling bytes are visible: {tail:?}");
    }

    #[test]
    fn genuinely_invalid_bytes_do_not_hold_the_stream_hostage() {
        let mut decoder = Utf8StreamDecoder::new();
        let out = decoder.push(b"ab\xFFcd\n\n");
        assert!(out.contains('�'), "invalid byte is substituted: {out:?}");
        assert!(out.contains("cd"), "decoding continues after it: {out:?}");
        assert_eq!(decoder.finish(), "");
    }
}
