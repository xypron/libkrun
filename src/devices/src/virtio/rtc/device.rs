// Copyright 2026 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-process vhost-device-rtc backend + a trimmed vhost-user frontend.

use std::fs;
use std::io::{self, ErrorKind, Result as IoResult};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::process;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use log::{debug, error, warn};
use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};
use utils::eventfd::{EFD_NONBLOCK, EventFd};
use vhost::vhost_user::message::VhostUserProtocolFeatures;
use vhost::vhost_user::{Frontend, Listener, VhostUserFrontend};
use vhost::{VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};
use vm_memory::{Address, GuestMemoryBackend, GuestMemoryMmap, GuestMemoryRegion};
use vmm_sys_util::eventfd::EventFd as VhostEventFd;

use crate::virtio::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, InterruptTransport, QueueConfig,
    VirtioDevice,
};

/// `VIRTIO_ID_CLOCK` from `linux/virtio_ids.h`.
pub const VIRTIO_ID_CLOCK: u32 = 17;

const NUM_QUEUES: usize = 2;
/// Matches `VhostUserRtcBackend::max_queue_size()` upstream.
const QUEUE_SIZE: u16 = 1024;
static RTC_SOCK_COUNTER: AtomicU32 = AtomicU32::new(0);

#[derive(Debug)]
pub enum RtcError {
    Io(io::Error),
}

impl std::fmt::Display for RtcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RtcError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

/// Spawns `vhost-device-rtc`'s backend on a dedicated thread, listening
/// on a private, per-VM named Unix socket, and returns the connected
/// frontend `RtcDevice` once the backend has accepted.
///
/// The socket lives in a per-process, mode-0700 subdirectory under
/// [`std::env::temp_dir`], so no other local user can even list its
/// name while the VM is running; the directory (and its one socket
/// file) is removed once the frontend has connected.
pub fn spawn_backend() -> Result<RtcDevice, RtcError> {
    let dir_name = format!(
        "krun-rtc-{}-{}",
        process::id(),
        RTC_SOCK_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let dir = std::env::temp_dir().join(dir_name);
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(RtcError::Io)?;
    let socket_path = dir.join("rtc.sock");

    // `Listener::new()` unlinks any stale socket, then `bind()`s the
    // `UnixListener` (bind on a Unix socket also listens), so the
    // connection made below is queued in the backlog even if the
    // backend thread has not reached `accept()` yet: no race.
    let mut listener = Listener::new(&socket_path, true)
        .map_err(|e| RtcError::Io(io::Error::other(format!("Listener::new: {e}"))))?;

    // Offer all three default clocks (UTC, TAI, monotonic) plus alarm
    // support -- vhost-device-rtc already implements PTP cross-
    // timestamping and the full alarm protocol unconditionally.
    let config = vhost_device_rtc::RtcConfiguration {
        offer_alarm: true,
        utc: true,
        tai: true,
        monotonic: true,
    };

    let backend_thread = thread::Builder::new()
        .name("vhost-device-rtc".into())
        .spawn(move || {
            // Handles exactly the one connection libkrun's frontend
            // makes below, and returns once it disconnects.
            if let Err(e) = vhost_device_rtc::start_backend(&mut listener, config) {
                error!("vhost-device-rtc: backend exited with error: {e}");
            }
        })
        .map_err(RtcError::Io)?;

    let device = RtcDevice::connect(&socket_path, backend_thread);
    // The frontend has connected (or failed to) by now; the socket's
    // directory entry is no longer needed either way.
    let _ = fs::remove_dir_all(&dir);
    device
}

/// Minimal vhost-user frontend for the always-on default virtio-rtc
/// device. Unlike [`crate::virtio::vhost_user::VhostUserDevice`], this
/// has no GPU socket, display backend, or BACKEND_REQ/SHMEM handling:
/// vhost-device-rtc only ever needs two plain virtqueues.
pub struct RtcDevice {
    frontend: Arc<Mutex<Frontend>>,
    /// Second handle on the vhost-user socket, used to disconnect the
    /// backend on drop regardless of who else still holds the frontend.
    stream: UnixStream,
    /// The in-process vhost-device-rtc backend; joined on drop.
    backend_thread: Option<JoinHandle<()>>,
    queue_configs: [QueueConfig; NUM_QUEUES],
    avail_features: u64,
    has_protocol_features: bool,
    acked_features: u64,
    device_state: DeviceState,
    activate_evt: EventFd,
    vring_call_event: Option<EventFd>,
}

impl RtcDevice {
    fn connect(
        socket_path: &std::path::Path,
        backend_thread: JoinHandle<()>,
    ) -> Result<Self, RtcError> {
        let stream = UnixStream::connect(socket_path).map_err(RtcError::Io)?;
        let stream_handle = stream.try_clone().map_err(RtcError::Io)?;
        let mut frontend = Frontend::from_stream(stream, NUM_QUEUES as u64);

        let avail_features = frontend
            .get_features()
            .map_err(|e| RtcError::Io(io::Error::other(format!("get_features: {e}"))))?;

        const VHOST_USER_F_PROTOCOL_FEATURES: u64 = 1 << 30;
        let has_protocol_features = avail_features & VHOST_USER_F_PROTOCOL_FEATURES != 0;
        let avail_features = avail_features & !VHOST_USER_F_PROTOCOL_FEATURES;

        if has_protocol_features {
            let protocol_features = frontend.get_protocol_features().map_err(|e| {
                RtcError::Io(io::Error::other(format!("get_protocol_features: {e}")))
            })?;
            // vhost-device-rtc only ever advertises MQ; negotiate exactly
            // that, nothing else (no CONFIG/BACKEND_REQ/SHMEM for RTC).
            let negotiated = protocol_features & VhostUserProtocolFeatures::MQ;
            frontend.set_protocol_features(negotiated).map_err(|e| {
                RtcError::Io(io::Error::other(format!("set_protocol_features: {e}")))
            })?;
        }

        Ok(Self {
            frontend: Arc::new(Mutex::new(frontend)),
            stream: stream_handle,
            backend_thread: Some(backend_thread),
            queue_configs: [QueueConfig::new(QUEUE_SIZE); NUM_QUEUES],
            avail_features,
            has_protocol_features,
            acked_features: 0,
            device_state: DeviceState::Inactive,
            activate_evt: EventFd::new(EFD_NONBLOCK).map_err(RtcError::Io)?,
            vring_call_event: None,
        })
    }

    /// Activate the vhost-user device by setting up memory and vrings.
    /// Trimmed-down counterpart of `VhostUserDevice::activate_vhost_user`:
    /// no GPU socket, no BACKEND_REQ (vhost-device-rtc never advertises
    /// SHMEM/BACKEND_REQ since it has no shared-memory regions).
    fn activate_vhost_user(
        &mut self,
        mem: &GuestMemoryMmap,
        queues: &[DeviceQueue],
    ) -> IoResult<()> {
        const VHOST_USER_F_PROTOCOL_FEATURES: u64 = 1 << 30;
        let mut frontend = self.frontend.lock().unwrap();

        debug!("rtc: activating vhost-user device");

        let backend_feature_bits = if self.has_protocol_features {
            self.acked_features | VHOST_USER_F_PROTOCOL_FEATURES
        } else {
            self.acked_features
        };

        frontend.set_owner().map_err(io::Error::other)?;

        let regions = mem_table(mem)?;

        frontend.set_mem_table(&regions).map_err(|e| {
            error!("rtc: set_mem_table failed: {e:?}");
            io::Error::other(e)
        })?;

        frontend
            .set_features(backend_feature_bits)
            .map_err(io::Error::other)?;

        let vring_call_event = EventFd::new(EFD_NONBLOCK)?;

        for (queue_index, device_queue) in queues.iter().enumerate() {
            let queue = &device_queue.queue;

            frontend
                .set_vring_num(queue_index, queue.actual_size())
                .map_err(io::Error::other)?;
            frontend
                .set_vring_base(queue_index, 0)
                .map_err(io::Error::other)?;

            let desc_table_gpa = queue.desc_table.0;
            let avail_ring_gpa = queue.avail_ring.0;
            let used_ring_gpa = queue.used_ring.0;

            let gpa_to_vmm = |gpa: u64| -> IoResult<u64> {
                mem.get_host_address(Address::new(gpa))
                    .map(|a| a as u64)
                    .map_err(|_| {
                        io::Error::new(
                            ErrorKind::InvalidInput,
                            format!("GPA 0x{gpa:x} not found in any memory region"),
                        )
                    })
            };

            let vring_config = VringConfigData {
                flags: 0,
                queue_max_size: queue.get_max_size(),
                queue_size: queue.actual_size(),
                desc_table_addr: gpa_to_vmm(desc_table_gpa)?,
                used_ring_addr: gpa_to_vmm(used_ring_gpa)?,
                avail_ring_addr: gpa_to_vmm(avail_ring_gpa)?,
                log_addr: None,
            };

            frontend
                .set_vring_addr(queue_index, &vring_config)
                .map_err(|e| {
                    error!("rtc: set_vring_addr failed: {e:?}");
                    io::Error::other(e)
                })?;

            // Bridge krun_utils::EventFd with vmm_sys_util::EventFd type mismatch.
            let kick_fd = unsafe { VhostEventFd::from_raw_fd(device_queue.event.as_raw_fd()) };
            frontend
                .set_vring_kick(queue_index, &kick_fd)
                .map_err(|e| {
                    error!("rtc: set_vring_kick failed: {e:?}");
                    io::Error::other(e)
                })?;
            std::mem::forget(kick_fd);

            let call_fd = unsafe { VhostEventFd::from_raw_fd(vring_call_event.as_raw_fd()) };
            frontend
                .set_vring_call(queue_index, &call_fd)
                .map_err(|e| {
                    error!("rtc: set_vring_call failed: {e:?}");
                    io::Error::other(e)
                })?;
            std::mem::forget(call_fd);

            if self.has_protocol_features {
                frontend
                    .set_vring_enable(queue_index, true)
                    .map_err(io::Error::other)?;
            }
        }

        self.vring_call_event = Some(vring_call_event);
        debug!("rtc: vhost-user device activated successfully");
        Ok(())
    }
}

/// Builds the vhost-user memory table for `mem`.
///
/// Every region must be file-backed so the backend can map it; a
/// region without a file is an error rather than being silently left
/// out of the table.
fn mem_table(mem: &GuestMemoryMmap) -> IoResult<Vec<VhostUserMemoryRegionInfo>> {
    // Can't use from_guest_region(): vhost 0.17 expects vm-memory 0.18 types.
    mem.iter()
        .map(|region| {
            let file_offset = region.file_offset().ok_or_else(|| {
                io::Error::new(
                    ErrorKind::InvalidInput,
                    "rtc vhost-user backend requires file-backed guest memory",
                )
            })?;
            Ok(VhostUserMemoryRegionInfo {
                guest_phys_addr: region.start_addr().raw_value(),
                memory_size: region.len(),
                userspace_addr: region.as_ptr() as u64,
                mmap_offset: file_offset.start(),
                mmap_handle: file_offset.file().as_raw_fd(),
            })
        })
        .collect()
}

impl Drop for RtcDevice {
    fn drop(&mut self) {
        // Disconnect the backend: it sees EOF, treats it as a normal
        // shutdown and returns from `start_backend()`.
        let _ = self.stream.shutdown(Shutdown::Both);
        if let Some(thread) = self.backend_thread.take()
            && thread.join().is_err()
        {
            warn!("rtc: vhost-device-rtc backend thread panicked");
        }
    }
}

impl VirtioDevice for RtcDevice {
    fn device_type(&self) -> u32 {
        VIRTIO_ID_CLOCK
    }

    fn device_name(&self) -> &str {
        "rtc"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &self.queue_configs
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn read_config(&self, _offset: u64, data: &mut [u8]) {
        // vhost-device-rtc has no device-specific config space.
        data.fill(0);
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {}

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if let Err(e) = self.activate_vhost_user(&mem, &queues) {
            error!("rtc: failed to activate vhost-user device: {e}");
            return Err(ActivateError::BadActivate);
        }

        self.device_state = DeviceState::Activated(mem, interrupt);

        if let Err(e) = self.activate_evt.write(1) {
            error!("rtc: failed to write activate event: {e}");
            return Err(ActivateError::BadActivate);
        }

        Ok(())
    }

    fn is_activated(&self) -> bool {
        matches!(self.device_state, DeviceState::Activated(_, _))
    }

    fn reset(&mut self) -> bool {
        debug!("rtc: resetting vhost-user device");
        if let Ok(mut frontend) = self.frontend.lock() {
            for queue_index in 0..self.queue_configs.len() {
                if let Err(e) = frontend.set_vring_enable(queue_index, false) {
                    debug!("rtc: failed to disable vring {queue_index} during reset: {e}");
                }
            }
        }
        self.vring_call_event = None;
        self.device_state = DeviceState::Inactive;
        true
    }
}

impl RtcDevice {
    fn handle_vring_call_event(&mut self, event: &EpollEvent) {
        let event_set = event.event_set();
        if !event_set.contains(EventSet::IN) {
            warn!("rtc: vring call unexpected event {event_set:?}");
            return;
        }

        if let Some(ref vring_call_event) = self.vring_call_event {
            if let Err(e) = vring_call_event.read() {
                error!("rtc: failed to read vring_call_event: {e}");
                return;
            }
        } else {
            error!("rtc: vring_call_event is None");
            return;
        }

        if let DeviceState::Activated(_, ref interrupt) = self.device_state {
            interrupt.signal_used_queue();
        }
    }

    fn handle_activate_event(&mut self, event_manager: &mut EventManager) {
        if let Err(e) = self.activate_evt.read() {
            error!("rtc: failed to consume activate event: {e}");
        }

        if let Some(ref vring_call_event) = self.vring_call_event {
            let self_subscriber = event_manager
                .subscriber(self.activate_evt.as_raw_fd())
                .unwrap();

            event_manager
                .register(
                    vring_call_event.as_raw_fd(),
                    EpollEvent::new(EventSet::IN, vring_call_event.as_raw_fd() as u64),
                    self_subscriber,
                )
                .unwrap_or_else(|e| {
                    error!("rtc: failed to register vring_call_event with event manager: {e:?}");
                });
        } else {
            error!("rtc: vring_call_event is None during activation");
        }

        event_manager
            .unregister(self.activate_evt.as_raw_fd())
            .unwrap_or_else(|e| {
                error!("rtc: failed to unregister activate event: {e:?}");
            });
    }
}

impl Subscriber for RtcDevice {
    fn process(&mut self, event: &EpollEvent, event_manager: &mut EventManager) {
        let source = event.fd();
        let activate_evt_fd = self.activate_evt.as_raw_fd();
        let vring_call_fd = self
            .vring_call_event
            .as_ref()
            .map(|e| e.as_raw_fd())
            .unwrap_or(-1);

        if self.is_activated() {
            match source {
                _ if source == vring_call_fd => self.handle_vring_call_event(event),
                _ if source == activate_evt_fd => self.handle_activate_event(event_manager),
                _ => warn!("rtc: unexpected event received: {source:?}"),
            }
        } else if source == activate_evt_fd {
            self.handle_activate_event(event_manager);
        } else {
            warn!("rtc: device not yet activated, spurious event received: {source:?}");
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        vec![EpollEvent::new(
            EventSet::IN,
            self.activate_evt.as_raw_fd() as u64,
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vm_memory::GuestAddress;

    const VIRTIO_F_VERSION_1: u64 = 1 << 32;

    #[test]
    fn mem_table_rejects_non_file_backed_memory() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let err = mem_table(&mem).err().unwrap();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn spawn_backend_negotiates_features() {
        let dev = spawn_backend().unwrap();
        assert_eq!(dev.device_type(), VIRTIO_ID_CLOCK);
        assert_eq!(dev.queue_config().len(), NUM_QUEUES);
        assert_ne!(dev.avail_features() & VIRTIO_F_VERSION_1, 0);
        assert!(dev.has_protocol_features);
    }

    #[test]
    fn spawn_and_drop_does_not_hang() {
        for _ in 0..8 {
            drop(spawn_backend().unwrap());
        }
    }
}
