#[cfg(feature = "qperf-trace")]
fn phase_marker_from_line(line: &[u8]) -> Option<(axtask::qperf_trace::PhaseBoundary, &[u8])> {
    use axtask::qperf_trace::PhaseBoundary;

    let line = &line[line
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(line.len())..];
    let has_word_prefix = |prefix: &[u8]| {
        line.strip_prefix(prefix)
            .is_some_and(|rest| rest.first().is_none_or(u8::is_ascii_whitespace))
    };
    if has_word_prefix(b"BUILDSTORM_BEGIN") {
        return Some((PhaseBoundary::Begin, b"buildstorm"));
    }
    if has_word_prefix(b"BUILDSTORM_COMPILE") {
        return Some((PhaseBoundary::End, b"buildstorm"));
    }

    for (prefix, boundary) in [
        (b"QPERF_PHASE_BEGIN".as_slice(), PhaseBoundary::Begin),
        (b"QPERF_PHASE_END".as_slice(), PhaseBoundary::End),
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

#[cfg(feature = "qperf-trace")]
pub(super) struct OutputMarkerScanner {
    fd: usize,
    line: [u8; 64],
    line_len: usize,
    emitted: bool,
}

#[cfg(feature = "qperf-trace")]
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
        #[cfg(feature = "qperf-trace")]
        if let Some((boundary, phase)) = phase_marker_from_line(&self.line[..self.line_len]) {
            axtask::qperf_trace::phase_marker(boundary, phase);
            if phase == b"buildstorm" {
                match boundary {
                    axtask::qperf_trace::PhaseBoundary::Begin => axfs::buildstorm_stats::begin(),
                    axtask::qperf_trace::PhaseBoundary::End => axfs::buildstorm_stats::finish(),
                }
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

#[cfg(feature = "qperf-trace")]
impl Drop for OutputMarkerScanner {
    fn drop(&mut self) {
        if self.line_len != 0 && !self.emitted {
            self.emit_marker();
        }
    }
}

#[cfg(all(test, feature = "qperf-trace"))]
mod phase_marker_tests {
    use axtask::qperf_trace::PhaseBoundary;

    use super::phase_marker_from_line;

    #[test]
    fn recognizes_buildstorm_and_generic_phase_lines() {
        assert_eq!(
            phase_marker_from_line(b"BUILDSTORM_BEGIN mode=multi"),
            Some((PhaseBoundary::Begin, b"buildstorm".as_slice()))
        );
        assert_eq!(
            phase_marker_from_line(b"BUILDSTORM_COMPILE mode=multi ok=true"),
            Some((PhaseBoundary::End, b"buildstorm".as_slice()))
        );
        assert_eq!(phase_marker_from_line(b"BUILDSTORM_BEGINNING"), None);
        assert_eq!(phase_marker_from_line(b"BUILDSTORM_COMPILE_EXTRA"), None);
        assert_eq!(
            phase_marker_from_line(b"QPERF_PHASE_BEGIN link-stage"),
            Some((PhaseBoundary::Begin, b"link-stage".as_slice()))
        );
        assert_eq!(
            phase_marker_from_line(b"QPERF_PHASE_END link-stage"),
            Some((PhaseBoundary::End, b"link-stage".as_slice()))
        );
    }

    #[test]
    fn rejects_invalid_or_oversized_generic_phase_names() {
        assert_eq!(phase_marker_from_line(b"QPERF_PHASE_BEGIN"), None);
        assert_eq!(phase_marker_from_line(b"QPERF_PHASE_BEGIN bad/name"), None);
        assert_eq!(
            phase_marker_from_line(b"QPERF_PHASE_BEGIN phase-name-too-long"),
            None
        );
    }
}
