//
// Copyright 2023 The Project Oak Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

extern crate log;

use std::str::FromStr;

use anyhow::anyhow;
use log::LevelFilter;
use syslog::{BasicLogger, Facility, Formatter3164};

/// Kernel command-line token that selects the max log level, e.g.
/// `oak_log_level=debug` (accepts off/error/warn/info/debug/trace,
/// case-insensitive). The host sets it via the launcher's
/// `--kernel-cmdline-extra` flag (which `run.sh` drives), so verbosity is
/// configurable per run without rebuilding the guest.
const CMDLINE_LOG_LEVEL_KEY: &str = "oak_log_level";

/// Fallback env var (e.g. set in the systemd unit) if the cmdline token is
/// absent.
const LOG_LEVEL_ENV: &str = "OAK_LOG_LEVEL";

/// The level used when neither the cmdline token nor the env var is set/valid.
const DEFAULT_LOG_LEVEL: LevelFilter = LevelFilter::Debug;

/// Reads `oak_log_level=<level>` from the guest kernel command line.
fn level_from_cmdline() -> Option<LevelFilter> {
    let cmdline = std::fs::read_to_string("/proc/cmdline").ok()?;
    cmdline
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix(CMDLINE_LOG_LEVEL_KEY).and_then(|r| r.strip_prefix('=')))
        .and_then(|v| LevelFilter::from_str(v).ok())
}

/// Setup logging to syslog.
pub fn setup() -> anyhow::Result<()> {
    // Based on syslog's example of integrating with the log crate.
    // Ref: https://docs.rs/syslog/6.1.0/syslog/

    let formatter = Formatter3164 {
        facility: Facility::LOG_DAEMON,
        hostname: None,
        process: "oak_containers_orchestrator".into(),
        pid: std::process::id(),
    };

    let logger =
        syslog::unix(formatter).map_err(|e| anyhow!("impossible to connect to syslog: {:?}", e))?;

    // Level precedence: kernel cmdline `oak_log_level=` (host/run.sh controlled),
    // then the OAK_LOG_LEVEL env var, then the default (debug). NOTE: at debug the
    // orchestrator's dependencies produce a high log volume; the journald overlay
    // (larger volatile journal + no rate limiting) and the launcher console-forwarder
    // fix keep that from dropping the tail. See docs/orchestrator-log-drops-journald.md.
    let level = level_from_cmdline()
        .or_else(|| {
            std::env::var(LOG_LEVEL_ENV).ok().and_then(|v| LevelFilter::from_str(v.trim()).ok())
        })
        .unwrap_or(DEFAULT_LOG_LEVEL);
    log::set_boxed_logger(Box::new(BasicLogger::new(logger)))
        .map(|()| log::set_max_level(level))
        .map_err(|e| anyhow!("failed to set logger: {:?}", e))?;
    log::info!("orchestrator log level = {level} (set kernel arg {CMDLINE_LOG_LEVEL_KEY}=<level>)");

    Ok(())
}
