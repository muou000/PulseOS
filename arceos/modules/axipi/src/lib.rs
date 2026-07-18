//! [ArceOS](https://github.com/arceos-org/arceos) Inter-Processor Interrupt (IPI) primitives.

#![cfg_attr(not(test), no_std)]

#[macro_use]
extern crate log;
extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering};

use axhal::{
    irq::{IPI_IRQ, IpiError, IpiTarget},
    percpu::this_cpu_id,
};
use kspin::SpinNoIrq;
use lazyinit::LazyInit;

mod event;
mod queue;

pub use event::{Callback, MulticastCallback};
use queue::IpiEventQueue;

#[percpu::def_percpu]
static IPI_EVENT_QUEUE: LazyInit<SpinNoIrq<IpiEventQueue>> = LazyInit::new();

static IPI_CPU_READY: [AtomicBool; axconfig::plat::MAX_CPU_NUM] =
    [const { AtomicBool::new(false) }; axconfig::plat::MAX_CPU_NUM];

/// Initialize the per-CPU IPI event queue.
pub fn init() {
    IPI_EVENT_QUEUE.with_current(|ipi_queue| {
        ipi_queue.init_once(SpinNoIrq::new(IpiEventQueue::default()));
    });
}

/// Marks the current CPU ready to receive IPI callbacks.
pub fn mark_current_cpu_ready() {
    IPI_CPU_READY[this_cpu_id()].store(true, Ordering::Release);
}

/// Waits until all online CPUs can receive IPI callbacks.
pub fn wait_for_all_cpus_ready() {
    while (0..axhal::cpu_num()).any(|cpu_id| {
        axhal::is_cpu_online(cpu_id) && !IPI_CPU_READY[cpu_id].load(Ordering::Acquire)
    }) {
        core::hint::spin_loop();
    }
}

/// Executes a callback on the specified destination CPU via IPI.
pub fn run_on_cpu<T: Into<Callback>>(dest_cpu: usize, callback: T) -> Result<(), IpiError> {
    debug!("Send IPI event to CPU {}", dest_cpu);
    if dest_cpu == this_cpu_id() {
        // Execute callback on current CPU immediately
        callback.into().call();
        Ok(())
    } else {
        if dest_cpu >= axhal::cpu_num() {
            return Err(IpiError::InvalidTarget);
        }
        if !axhal::is_cpu_online(dest_cpu) || !IPI_CPU_READY[dest_cpu].load(Ordering::Acquire) {
            return Err(IpiError::CpuOffline);
        }

        let mut queue = unsafe { IPI_EVENT_QUEUE.remote_ref_raw(dest_cpu) }.lock();
        queue.push(this_cpu_id(), callback.into());
        if let Err(error) = axhal::irq::send_ipi(IPI_IRQ, IpiTarget::Other { cpu_id: dest_cpu }) {
            queue.pop_back();
            return Err(error);
        }
        Ok(())
    }
}

/// Executes a callback on all other CPUs via IPI.
pub fn run_on_each_cpu<T: Into<MulticastCallback>>(callback: T) -> Result<(), IpiError> {
    debug!("Send IPI event to all other CPUs");
    let current_cpu_id = this_cpu_id();
    let cpu_num = axhal::cpu_num();
    let callback = callback.into();

    // Execute callback on current CPU immediately
    callback.clone().call();
    // Queue and signal each target atomically so a failed send can be rolled back.
    for cpu_id in 0..cpu_num {
        if cpu_id != current_cpu_id && axhal::is_cpu_online(cpu_id) {
            run_on_cpu(cpu_id, callback.clone().into_unicast())?;
        }
    }
    Ok(())
}

/// The handler for IPI events. It retrieves the events from the queue and calls the corresponding callbacks.
pub fn ipi_handler() {
    while let Some((src_cpu_id, callback)) = unsafe { IPI_EVENT_QUEUE.current_ref_mut_raw() }
        .lock()
        .pop_one()
    {
        debug!("Received IPI event from CPU {}", src_cpu_id);
        callback.call();
    }
}
