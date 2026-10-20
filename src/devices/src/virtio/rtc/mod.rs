// Copyright 2026 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! virtio-rtc: the default RTC device on Linux/KVM.
//!
//! Rather than reimplementing the virtio-rtc protocol, this runs
//! `rust-vmm/vhost-device`'s `vhost-device-rtc` vhost-user backend
//! in-process (own thread), and connects to it through a minimal,
//! RTC-specific vhost-user frontend (`RtcDevice`) implemented in this
//! module. `vhost-device-rtc` already implements the full protocol,
//! including PTP cross-timestamping and alarm support, so no protocol
//! code lives in libkrun itself.
//!
//! `RtcDevice` is a deliberately trimmed-down cousin of
//! [`crate::virtio::vhost_user::VhostUserDevice`]: no GPU socket,
//! display backend, or BACKEND_REQ/SHMEM handling, since the RTC
//! backend only ever needs two plain virtqueues (`requestq`/`alarmq`).
//! This keeps the always-on default RTC free of the `krun_display`/
//! bindgen build dependency that the general-purpose, opt-in
//! `vhost-user` feature pulls in for GPU/media backends.

mod device;

pub use device::{RtcDevice, RtcError, VIRTIO_ID_CLOCK, spawn_backend};
