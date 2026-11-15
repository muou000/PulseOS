#[cfg(test)]
#[path = "../../../modules/axfs/src/highlevel/file/position.rs"]
mod position;

#[cfg(test)]
mod tests {
    use super::position::{FilePosition, IoPosition};
    use futures_lite::future::block_on;

    #[test]
    fn one_operation_keeps_position_exclusive_across_completed_windows() {
        block_on(async {
            let position = FilePosition::new(7);
            let mut operation = IoPosition::begin(Some(&position), None).await;
            assert_eq!(operation.offset(), 7);
            operation.advance(3).unwrap();
            assert_eq!(operation.offset(), 10);
            assert!(position.try_lock().is_none());
            operation.advance(5).unwrap();
            drop(operation);
            assert_eq!(*position.try_lock().unwrap(), 15);
        });
    }

    #[test]
    fn positioned_append_never_waits_for_or_updates_shared_position() {
        block_on(async {
            let position = FilePosition::new(19);
            let shared = position.lock().await;
            let mut operation = IoPosition::begin(Some(&position), Some(3)).await;
            operation.select_append(100);
            assert_eq!(operation.validation_offset(), 3);
            operation.advance(8).unwrap();
            assert_eq!(operation.offset(), 108);
            assert_eq!(*shared, 19);
        });
    }

    #[test]
    fn append_with_no_progress_preserves_old_shared_offset() {
        block_on(async {
            let position = FilePosition::new(7);
            let mut operation = IoPosition::begin(Some(&position), None).await;
            operation.select_append(100);
            assert_eq!(operation.validation_offset(), 7);
            operation.advance(0).unwrap();
            drop(operation);
            assert_eq!(*position.try_lock().unwrap(), 7);
        });
    }

    #[test]
    fn overflow_does_not_publish_an_uncompleted_position() {
        block_on(async {
            let position = FilePosition::new(u64::MAX - 3);
            let mut operation = IoPosition::begin(Some(&position), None).await;
            operation.advance(2).unwrap();
            assert!(operation.advance(2).is_none());
            drop(operation);
            assert_eq!(*position.try_lock().unwrap(), u64::MAX - 1);
        });
    }

    #[test]
    fn cancelling_a_queued_operation_does_not_disable_resident_reads() {
        block_on(async {
            let position = FilePosition::new(0);
            let shared = position.lock().await;
            {
                let mut pending = core::pin::pin!(IoPosition::begin(Some(&position), None));
                assert!(futures_lite::future::poll_once(&mut pending).await.is_none());
            }
            drop(shared);
            assert_eq!(*position.try_lock().unwrap(), 0);
        });
    }
}
