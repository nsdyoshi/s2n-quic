// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! This module contains abstractions around the platform on which the
//! stack is running

#![cfg_attr(not(any(test, feature = "std")), no_std)]

extern crate alloc;

#[macro_use]
mod macros;

#[cfg(target_os = "linux")]
pub mod xdp;

pub mod buffer;
pub mod io;
pub mod message;
pub mod socket;
pub mod time;
