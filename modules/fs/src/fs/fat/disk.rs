use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll, ready},
};

use axdriver::prelude::{AsyncBlockDriverOps, DevError, DevResult};
use vfs::{VfsError, VfsResult};
use hadris_io::{Error, ErrorKind, ErrorType};
use hadris_storage::{BlockIndex, BlockSize, async_::BlockDevice};

#[derive(Debug)]
pub(super) struct FatDiskError(pub(super) DevError);

impl fmt::Display for FatDiskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl core::error::Error for FatDiskError {}

type Request = Pin<Box<dyn Future<Output = DevResult<Vec<u8>>> + Send>>;

#[derive(Default)]
pub(super) struct RequestState {
    pending: Option<Request>,
    mutating: bool,
}

pub(super) struct FatDisk<D> {
    dev: Arc<D>,
    block_size: BlockSize,
    cancelled: Option<Request>,
}

impl<D: AsyncBlockDriverOps + 'static> FatDisk<D> {
    pub(super) fn new(dev: D) -> VfsResult<Self> {
        let block_size = u32::try_from(dev.block_size())
            .ok()
            .and_then(BlockSize::new)
            .ok_or(VfsError::InvalidInput)?;
        Ok(Self {
            dev: Arc::new(dev),
            block_size,
            cancelled: None,
        })
    }

    fn check_range(&self, first: BlockIndex, len: usize) -> Result<(), Error<FatDiskError>> {
        let size = self.block_size.get() as usize;
        let blocks = (len / size) as u64;
        if !len.is_multiple_of(size)
            || first
                .get()
                .checked_add(blocks)
                .is_none_or(|end| end > self.dev.num_blocks())
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid FAT block range",
            ));
        }
        Ok(())
    }

    fn poll_request(
        &mut self,
        state: &mut RequestState,
        cx: &mut Context<'_>,
        start: impl FnOnce(Arc<D>) -> Request,
    ) -> Poll<Result<Vec<u8>, Error<FatDiskError>>> {
        // A cancelled write might already be on the device queue. Complete it
        // before allowing the filesystem to retry or roll back that operation.
        if let Some(cancelled) = self.cancelled.as_mut() {
            let result = ready!(cancelled.as_mut().poll(cx));
            self.cancelled = None;
            result.map_err(device_error)?;
        }
        let request = state
            .pending
            .get_or_insert_with(|| start(Arc::clone(&self.dev)));
        let result = ready!(request.as_mut().poll(cx));
        state.pending = None;
        Poll::Ready(result.map_err(device_error))
    }
}

fn device_error(error: DevError) -> Error<FatDiskError> {
    Error::device(FatDiskError(error), "FAT block device request failed")
}

impl<D> ErrorType for FatDisk<D> {
    type Error = FatDiskError;
}

impl<D: AsyncBlockDriverOps + 'static> BlockDevice for FatDisk<D> {
    type State = RequestState;

    fn block_size(&self) -> BlockSize {
        self.block_size
    }

    fn block_count(&self) -> u64 {
        self.dev.num_blocks()
    }

    fn writable(&self) -> bool {
        true
    }

    fn poll_read_blocks(
        &mut self,
        state: &mut Self::State,
        cx: &mut Context<'_>,
        first: BlockIndex,
        buf: &mut [u8],
    ) -> Poll<Result<(), Error<Self::Error>>> {
        self.check_range(first, buf.len())?;
        let len = buf.len();
        if len == 0 {
            return Poll::Ready(Ok(()));
        }

        // Hadris lends the destination for a single poll; the driver borrows
        // its destination for the whole future. Keep a private buffer between
        // polls and copy only when the device has finished.
        state.mutating = false;
        let bytes = ready!(self.poll_request(state, cx, |dev| Box::pin(async move {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(len)
                .map_err(|_| DevError::NoMemory)?;
            bytes.resize(len, 0);
            dev.read_block_async(first.get(), &mut bytes).await?;
            Ok(bytes)
        })))?;
        buf.copy_from_slice(&bytes);
        Poll::Ready(Ok(()))
    }

    fn poll_write_blocks(
        &mut self,
        state: &mut Self::State,
        cx: &mut Context<'_>,
        first: BlockIndex,
        buf: &[u8],
    ) -> Poll<Result<(), Error<Self::Error>>> {
        self.check_range(first, buf.len())?;
        if buf.is_empty() {
            return Poll::Ready(Ok(()));
        }

        state.mutating = true;
        self.poll_request(state, cx, |dev| {
            let mut bytes = Vec::new();
            if bytes.try_reserve_exact(buf.len()).is_err() {
                return Box::pin(core::future::ready(Err(DevError::NoMemory)));
            }
            bytes.extend_from_slice(buf);
            Box::pin(async move {
                dev.write_block_async(first.get(), &bytes).await?;
                Ok(Vec::new())
            })
        })
        .map(|result| result.map(drop))
    }

    fn poll_flush(
        &mut self,
        state: &mut Self::State,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Error<Self::Error>>> {
        state.mutating = true;
        self.poll_request(state, cx, |dev| {
            Box::pin(async move {
                dev.flush_async().await?;
                Ok(Vec::new())
            })
        })
        .map(|result| result.map(drop))
    }

    fn cancel(&mut self, state: &mut Self::State) {
        // If the dropped operation was still draining an earlier one, leave
        // the earlier request intact. The caller's slices are never retained.
        if let Some(request) = state.pending.take()
            && state.mutating
        {
            self.cancelled = Some(request);
        }
    }
}
