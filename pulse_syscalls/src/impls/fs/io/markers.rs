#[cfg(feature = "bpf-trace")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PhaseBoundary {
    Begin = 1,
    End   = 2,
}

#[cfg(feature = "bpf-trace")]
fn phase_marker_from_line(line: &[u8]) -> Option<(PhaseBoundary, &[u8])> {
    let line = &line[line
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(line.len())..];

    for (prefix, boundary) in [
        (b"BPF_PHASE_BEGIN".as_slice(), PhaseBoundary::Begin),
        (b"BPF_PHASE_END".as_slice(), PhaseBoundary::End),
        (b"PHASE_BEGIN".as_slice(), PhaseBoundary::Begin),
        (b"PHASE_END".as_slice(), PhaseBoundary::End),
    ] {
        let Some(rest) = line.strip_prefix(prefix) else {
            continue;
        };
        if !rest.first().is_some_and(u8::is_ascii_whitespace) {
            continue;
        }
        let rest = &rest[rest
            .iter()
            .position(|byte| !byte.is_ascii_whitespace())
            .unwrap_or(rest.len())..];
        let name_end = rest
            .iter()
            .position(u8::is_ascii_whitespace)
            .unwrap_or(rest.len());
        let name = &rest[..name_end];
        if !name.is_empty()
            && name.len() <= 16
            && name
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(byte))
        {
            return Some((boundary, name));
        }
    }
    None
}

#[cfg(feature = "bpf-trace")]
pub(super) struct OutputMarkerScanner {
    fd: usize,
    line: [u8; 64],
    line_len: usize,
    emitted: bool,
}

#[cfg(feature = "bpf-trace")]
impl OutputMarkerScanner {
    pub(super) fn new(fd: usize) -> Self {
        Self {
            fd,
            line: [0; 64],
            line_len: 0,
            emitted: false,
        }
    }

    pub(super) fn push(&mut self, bytes: &[u8]) {
        if !matches!(self.fd, 1 | 2) {
            return;
        }
        for &byte in bytes {
            if byte == b'\n' {
                self.finish_line();
            } else if self.line_len < self.line.len() {
                self.line[self.line_len] = byte;
                self.line_len += 1;
            } else if !self.emitted {
                self.emit_marker();
                self.emitted = true;
            }
        }
    }

    fn emit_marker(&self) {
        if let Some((boundary, phase)) = phase_marker_from_line(&self.line[..self.line_len]) {
            #[cfg(feature = "bpf-trace")]
            {
                axtask::bpf_trace::phase_marker(boundary as u32, phase);
            }
        }
    }

    fn finish_line(&mut self) {
        if !self.emitted {
            self.emit_marker();
        }
        self.line_len = 0;
        self.emitted = false;
    }
}

#[cfg(feature = "bpf-trace")]
impl Drop for OutputMarkerScanner {
    fn drop(&mut self) {
        if self.line_len != 0 && !self.emitted {
            self.emit_marker();
        }
    }
}

#[cfg(all(test, feature = "bpf-trace"))]
mod phase_marker_tests {
    use super::{PhaseBoundary, phase_marker_from_line};

    #[test]
    fn recognizes_bpf_and_generic_phase_lines() {
        assert_eq!(
            phase_marker_from_line(b"BPF_PHASE_BEGIN link-stage"),
            Some((PhaseBoundary::Begin, b"link-stage".as_slice()))
        );
        assert_eq!(
            phase_marker_from_line(b"BPF_PHASE_END link-stage"),
            Some((PhaseBoundary::End, b"link-stage".as_slice()))
        );
        assert_eq!(
            phase_marker_from_line(b"PHASE_BEGIN link-stage"),
            Some((PhaseBoundary::Begin, b"link-stage".as_slice()))
        );
        assert_eq!(
            phase_marker_from_line(b"PHASE_END link-stage"),
            Some((PhaseBoundary::End, b"link-stage".as_slice()))
        );
    }

    #[test]
    fn rejects_invalid_or_oversized_generic_phase_names() {
        assert_eq!(phase_marker_from_line(b"BPF_PHASE_BEGIN"), None);
        assert_eq!(phase_marker_from_line(b"BPF_PHASE_BEGIN bad/name"), None);
        assert_eq!(
            phase_marker_from_line(b"BPF_PHASE_BEGIN phase-name-too-long"),
            None
        );
    }
}
