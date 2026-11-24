use io::{BufReader, BufWriter, Cursor, SeekFrom, empty, prelude::*, repeat, sink};

#[test]
fn segmented_read_preserves_order_across_empty_and_partial_segments() {
    let mut reader = io::Segmented::new([&b""[..], &b"abc"[..], &b""[..], &b"defgh"[..]]);
    let mut first = [0; 5];
    assert_eq!(reader.remaining(), 8);
    assert_eq!(reader.read(&mut []).unwrap(), 0);
    assert_eq!(reader.read(&mut first).unwrap(), 5);
    assert_eq!(&first, b"abcde");
    assert_eq!(reader.remaining(), 3);
    let mut tail = [0xA5; 5];
    assert_eq!(reader.read(&mut tail).unwrap(), 3);
    assert_eq!(&tail, b"fgh\xA5\xA5");
    assert_eq!(reader.remaining(), 0);
    assert_eq!(reader.read(&mut tail).unwrap(), 0);
}

#[test]
fn segmented_write_fills_multiple_destinations_in_one_call() {
    let mut first = [0xA5; 5];
    let mut second = [0xA5; 6];
    {
        let segments = [&mut [][..], &mut first[1..4], &mut second[2..5]];
        let mut writer = io::Segmented::new(segments);
        assert_eq!(writer.remaining_mut(), 6);
        assert_eq!(writer.write(&[]).unwrap(), 0);
        assert_eq!(writer.write(b"abcde").unwrap(), 5);
        assert_eq!(writer.remaining_mut(), 1);
        assert_eq!(writer.write(b"fg").unwrap(), 1);
        assert_eq!(writer.remaining_mut(), 0);
        assert_eq!(writer.write(b"g").unwrap(), 0);
        writer.flush().unwrap();
    }
    assert_eq!(&first, b"\xA5abc\xA5");
    assert_eq!(&second, b"\xA5\xA5def\xA5");
}

#[test]
fn segmented_read_defers_an_error_until_after_delivering_the_prefix() {
    struct Flaky {
        bytes: &'static [u8],
        fail_once: bool,
    }
    impl IoBuf for Flaky {
        fn remaining(&self) -> usize {
            self.bytes.len()
        }
    }
    impl Read for Flaky {
        fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
            if core::mem::take(&mut self.fail_once) {
                return Err(io::Error::BadAddress);
            }
            self.bytes.read(dst)
        }
    }
    let mut reader = io::Segmented::new([
        Flaky {
            bytes: b"ab",
            fail_once: false,
        },
        Flaky {
            bytes: b"cd",
            fail_once: true,
        },
    ]);
    let mut dst = [0xA5; 4];
    assert_eq!(reader.read(&mut dst).unwrap(), 2);
    assert_eq!(dst, [b'a', b'b', 0xA5, 0xA5]);
    assert_eq!(reader.remaining(), 2);
    assert_eq!(reader.read(&mut []).unwrap(), 0);
    assert_eq!(reader.read(&mut dst), Err(io::Error::BadAddress));
    assert_eq!(reader.read(&mut dst).unwrap(), 2);
    assert_eq!(&dst[..2], b"cd");
}

#[test]
fn segmented_write_defers_an_error_until_after_delivering_the_prefix() {
    struct Flaky<'a> {
        bytes: &'a mut [u8],
        fail_once: bool,
    }
    impl IoBufMut for Flaky<'_> {
        fn remaining_mut(&self) -> usize {
            self.bytes.len()
        }
    }
    impl Write for Flaky<'_> {
        fn write(&mut self, src: &[u8]) -> io::Result<usize> {
            if core::mem::take(&mut self.fail_once) {
                return Err(io::Error::BadAddress);
            }
            self.bytes.write(src)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut first = [0xA5; 2];
    let mut last = [0xA5; 2];
    {
        let mut writer = io::Segmented::new([
            Flaky {
                bytes: &mut first,
                fail_once: false,
            },
            Flaky {
                bytes: &mut last,
                fail_once: true,
            },
        ]);
        assert_eq!(writer.write(b"abcd").unwrap(), 2);
        assert_eq!(writer.remaining_mut(), 2);
        assert_eq!(writer.write(&[]).unwrap(), 0);
        assert_eq!(writer.write(b"cd"), Err(io::Error::BadAddress));
        assert_eq!(writer.write(b"cd").unwrap(), 2);
    }
    assert_eq!(&first, b"ab");
    assert_eq!(&last, b"cd");
}

#[test]
fn segmented_read_stops_at_a_short_or_zero_transfer_without_skipping_data() {
    struct Limited {
        bytes: &'static [u8],
        limit: usize,
    }
    impl IoBuf for Limited {
        fn remaining(&self) -> usize {
            self.bytes.len()
        }
    }
    impl Read for Limited {
        fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
            let len = dst.len().min(self.limit);
            self.bytes.read(&mut dst[..len])
        }
    }
    let mut reader = io::Segmented::new([
        Limited {
            bytes: b"abc",
            limit: 2,
        },
        Limited {
            bytes: b"de",
            limit: 0,
        },
        Limited {
            bytes: b"fg",
            limit: 2,
        },
    ]);
    let mut dst = [0xA5; 7];
    assert_eq!(reader.read(&mut dst).unwrap(), 2);
    assert_eq!(dst, [b'a', b'b', 0xA5, 0xA5, 0xA5, 0xA5, 0xA5]);
    assert_eq!(reader.remaining(), 5);
    assert_eq!(reader.read(&mut dst).unwrap(), 1);
    assert_eq!(dst[0], b'c');
    assert_eq!(reader.remaining(), 4);
    assert_eq!(reader.read(&mut dst).unwrap(), 0);
    assert_eq!(reader.remaining(), 4);
}

#[test]
fn segmented_write_stops_at_a_short_or_zero_transfer_without_skipping_data() {
    struct Limited<'a> {
        bytes: &'a mut [u8],
        limit: usize,
    }
    impl IoBufMut for Limited<'_> {
        fn remaining_mut(&self) -> usize {
            self.bytes.len()
        }
    }
    impl Write for Limited<'_> {
        fn write(&mut self, src: &[u8]) -> io::Result<usize> {
            self.bytes.write(&src[..src.len().min(self.limit)])
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut first = [0xA5; 3];
    let mut middle = [0xA5; 2];
    let mut last = [0xA5; 2];
    {
        let mut writer = io::Segmented::new([
            Limited {
                bytes: &mut first,
                limit: 2,
            },
            Limited {
                bytes: &mut middle,
                limit: 0,
            },
            Limited {
                bytes: &mut last,
                limit: 2,
            },
        ]);
        assert_eq!(writer.write(b"abcdefg").unwrap(), 2);
        assert_eq!(writer.remaining_mut(), 5);
        assert_eq!(writer.write(b"cdefg").unwrap(), 1);
        assert_eq!(writer.remaining_mut(), 4);
        assert_eq!(writer.write(b"defg").unwrap(), 0);
        assert_eq!(writer.remaining_mut(), 4);
    }
    assert_eq!(&first, b"abc");
    assert_eq!(middle, [0xA5; 2]);
    assert_eq!(last, [0xA5; 2]);
}

#[test]
fn segmented_empty_lists_are_exhausted_without_access() {
    let mut reader = io::Segmented::new([] as [&[u8]; 0]);
    let mut dst = [0xA5; 3];
    assert_eq!(reader.remaining(), 0);
    assert_eq!(reader.read(&mut dst).unwrap(), 0);
    assert_eq!(dst, [0xA5; 3]);
    let mut writer = io::Segmented::new([] as [&mut [u8]; 0]);
    assert_eq!(writer.remaining_mut(), 0);
    assert_eq!(writer.write(b"abc").unwrap(), 0);
}

#[test]
fn test_slice() {
    let mut buf: &[u8] = &[1, 2, 3, 4, 5];
    assert_eq!(buf.remaining(), 5);

    buf.read(&mut [0; 2]).unwrap();
    assert_eq!(buf.remaining(), 3);

    let mut buf: &mut [u8] = &mut [0; 10];
    assert_eq!(buf.remaining_mut(), 10);

    buf.write(&[1, 2, 3, 4, 5]).unwrap();
    assert_eq!(buf.remaining_mut(), 5);
}

#[cfg(feature = "alloc")]
#[test]
fn test_vec() {
    let buf: Vec<u8> = vec![1, 2, 3, 4, 5];
    assert_eq!(buf.remaining(), 5);
    assert_eq!(buf.remaining_mut(), (isize::MAX as usize) - 5);

    let buf: &mut Vec<u8> = &mut vec![0; 10];
    assert_eq!(buf.remaining(), 10);

    let buf: Box<Vec<u8>> = Box::new(vec![1, 2, 3]);
    assert_eq!(buf.remaining(), 3);
    assert_eq!(buf.remaining_mut(), (isize::MAX as usize) - 3);
}

#[test]
fn test_chain() {
    let buf1: &[u8] = &[1, 2, 3];
    let buf2: &[u8] = &[4, 5];
    let mut chain = buf1.chain(buf2);
    assert_eq!(chain.remaining(), 5);

    chain.read(&mut [0; 2]).unwrap();
    assert_eq!(chain.remaining(), 3);

    chain.read(&mut [0; 1]).unwrap();
    assert_eq!(chain.remaining(), 2);

    chain.read(&mut [0; 2]).unwrap();
    assert_eq!(chain.remaining(), 0);
}

#[test]
fn test_cursor() {
    let data: &[u8] = &[1, 2, 3, 4, 5];
    let mut cursor = Cursor::new(data);

    assert_eq!(cursor.remaining(), 5);
    cursor.read(&mut [0; 2]).unwrap();
    assert_eq!(cursor.remaining(), 3);

    cursor.seek(SeekFrom::Start(0)).unwrap();
    assert_eq!(cursor.remaining(), 5);

    cursor.seek(SeekFrom::End(-2)).unwrap();
    assert_eq!(cursor.remaining(), 2);
}

#[test]
fn test_empty() {
    let mut empty = empty();
    assert_eq!(empty.remaining(), 0);
    assert_eq!(empty.remaining_mut(), usize::MAX);

    empty.read(&mut [0; 10]).unwrap();
    assert_eq!(empty.remaining(), 0);

    empty.write(&[1, 2, 3]).unwrap();
    assert_eq!(empty.remaining_mut(), usize::MAX);
}

#[test]
fn test_repeat() {
    let mut repeat = repeat(0u8);
    assert_eq!(repeat.remaining(), usize::MAX);

    repeat.read(&mut [0; 10]).unwrap();
    assert_eq!(repeat.remaining(), usize::MAX);
}

#[test]
fn test_sink() {
    let mut sink = sink();
    assert_eq!(sink.remaining_mut(), usize::MAX);

    sink.write(&[1, 2, 3, 4, 5]).unwrap();
    assert_eq!(sink.remaining_mut(), usize::MAX);
}

#[test]
fn test_take() {
    let data: &[u8] = &[1, 2, 3, 4, 5];
    let mut take = data.take(3);
    assert_eq!(take.remaining(), 3);

    take.read(&mut [0; 2]).unwrap();
    assert_eq!(take.remaining(), 1);

    take.read(&mut [0; 2]).unwrap();
    assert_eq!(take.remaining(), 0);

    let data: &[u8] = &[];
    let take = data.take(3);
    assert_eq!(take.remaining(), 0);
}

#[test]
fn test_bufreader() {
    let data: &[u8] = &[1, 2, 3, 4, 5];
    let mut reader = BufReader::with_capacity(2, data);
    assert_eq!(reader.remaining(), 5);

    reader.read(&mut [0; 1]).unwrap();
    assert_eq!(reader.remaining(), 4);

    assert_eq!(reader.read(&mut [0; 2]).unwrap(), 1);
    assert_eq!(reader.remaining(), 3);
}

#[test]
fn test_bufwriter() {
    let data: &mut [u8] = &mut [0; 5];
    let mut writer = BufWriter::new(data);
    assert_eq!(writer.remaining_mut(), 5);

    writer.write(&[1, 2, 3]).unwrap();
    assert_eq!(writer.remaining_mut(), 2);

    writer.write(&[4, 5, 6]).unwrap();
    assert_eq!(writer.remaining_mut(), 0);
}

#[test]
fn test_strict_write_to() {
    struct StrictWriter {
        rest: usize,
    }

    impl Write for StrictWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            assert!(buf.len() <= self.rest);
            let to_write = buf.len();
            self.rest -= to_write;
            Ok(to_write)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut writer = StrictWriter { rest: 5 };
    let mut buf: &[u8] = &[0; 5];

    assert_eq!(buf.write_to(&mut writer).unwrap(), 5);

    std::panic::catch_unwind(move || {
        let mut writer = StrictWriter { rest: 3 };
        let mut buf: &[u8] = &[0; 5];
        buf.write_to(&mut writer).unwrap();
    })
    .unwrap_err();
}

#[test]
fn test_strict_read_from() {
    struct StrictReader {
        rest: usize,
    }

    impl Read for StrictReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            assert!(buf.len() <= self.rest);
            let to_read = buf.len();
            self.rest -= to_read;
            for b in &mut buf[..to_read] {
                *b = 0;
            }
            Ok(to_read)
        }
    }

    let mut reader = StrictReader { rest: 5 };
    let mut buf: &mut [u8] = &mut [0; 5];

    assert_eq!(buf.read_from(&mut reader).unwrap(), 5);

    std::panic::catch_unwind(move || {
        let mut reader = StrictReader { rest: 3 };
        let mut buf: &mut [u8] = &mut [0; 5];
        buf.read_from(&mut reader).unwrap();
    })
    .unwrap_err();
}

#[test]
fn test_small_read_from() {
    struct SmallReader;

    impl Read for SmallReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let to_read = std::cmp::min(buf.len(), 3);
            for b in &mut buf[..to_read] {
                *b = 0;
            }
            Ok(to_read)
        }
    }

    let mut reader = SmallReader;
    let mut buf: &mut [u8] = &mut [0; 5];

    assert_eq!(buf.read_from(&mut reader).unwrap(), 3);
}
