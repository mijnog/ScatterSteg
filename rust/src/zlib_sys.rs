// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Maxime de Montbron

//! Raw zlib bindings, generated from the system's zlib.h by build.rs
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, dead_code, clippy::all)]
include!(concat!(env!("OUT_DIR"), "/zlib_bindings.rs"));
