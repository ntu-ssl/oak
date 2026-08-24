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

use std::{path::PathBuf, sync::Arc, time::Instant};

use anyhow::{anyhow, Context};
use clap::Parser;
use launcher_client::LauncherClient;
#[allow(deprecated)]
use oak_attestation::ApplicationKeysAttester;
use oak_attestation_types::{attester::Attester, util::Serializable};
use oak_containers_agent::{metrics::MetricsConfig, set_error_handler};
use oak_containers_attestation::generate_instance_keys;
use oak_proto_rust::oak::containers::v1::KeyProvisioningRole;
use prost::Message;
use tokio_util::sync::CancellationToken;

mod cdi;
pub mod confidential_transform;
pub mod container_runtime;
pub mod dice;
pub mod ipc_server;
pub mod key_provisioning;
pub mod launcher_client;
pub mod logging;
pub mod transform_crypto;
pub mod transform_session;
pub mod wasm_runtime;

#[derive(Parser, Debug)]
struct Args {
    #[arg(env, default_value = "http://10.0.2.100:8080")]
    launcher_addr: String,

    #[arg(default_value = "10.0.2.15:4000")]
    orchestrator_addr: String,

    #[arg(long, default_value = "/oak_container")]
    container_dir: PathBuf,

    #[arg(long, default_value = "/oak_utils/orchestrator_ipc")]
    ipc_socket_path: PathBuf,

    /// Address the ConfidentialTransform gRPC service binds to for a wasm
    /// session workload. Defaults to the port the Oak Containers launcher
    /// proxies the trusted app on (VM_LOCAL_PORT).
    #[arg(long, default_value = "0.0.0.0:8080")]
    confidential_transform_addr: String,

    #[arg(long, default_value = "oakc")]
    runtime_user: String,
}

#[allow(deprecated)]
pub async fn main<A: Attester + ApplicationKeysAttester + Serializable + 'static>(
) -> anyhow::Result<()> {
    crate::logging::setup()?;

    let args = Args::parse();

    let launcher_client = Arc::new(
        LauncherClient::create(args.launcher_addr.parse()?)
            .await
            .map_err(|error| anyhow!("couldn't create client: {:?}", error))?,
    );

    set_error_handler(|err| eprintln!("oak_containers_orchestrator: OTLP error: {}", err))?;

    let metrics_config = MetricsConfig {
        launcher_addr: args.launcher_addr,
        scope: "orchestrator",
        excluded_metrics: None,
    };

    let _oak_observer = oak_containers_agent::metrics::init_metrics(metrics_config);

    // Get key provisioning role.
    let key_provisioning_role = launcher_client
        .get_key_provisioning_role()
        .await
        .map_err(|error| anyhow!("couldn't get key provisioning role: {:?}", error))?;

    // Generate application keys.
    let t_startup = Instant::now();
    let t = Instant::now();
    let (instance_keys, instance_public_keys) = generate_instance_keys();
    log::info!("[timing] generate_instance_keys took {:.3} ms", t.elapsed().as_secs_f64() * 1e3);
    #[cfg(feature = "application_keys")]
    let (mut group_keys, group_public_keys) =
        if key_provisioning_role == KeyProvisioningRole::Leader {
            let (group_keys, group_public_keys) = instance_keys.generate_group_keys();
            (Some(Arc::new(group_keys)), Some(group_public_keys))
        } else {
            (None, None)
        };
    #[cfg(not(feature = "application_keys"))]
    let (mut group_keys, _group_public_keys) =
        if key_provisioning_role == KeyProvisioningRole::Leader {
            let (group_keys, group_public_keys) = instance_keys.generate_group_keys();
            (Some(Arc::new(group_keys)), Some(group_public_keys))
        } else {
            (None, None)
        };

    // Load application.
    let t = Instant::now();
    let container_bundle = launcher_client
        .get_container_bundle()
        .await
        .map_err(|error| anyhow!("couldn't get container bundle: {:?}", error))?;
    log::info!(
        "[timing] get_container_bundle took {:.3} ms",
        t.elapsed().as_secs_f64() * 1e3
    );
    let t = Instant::now();
    let application_config = launcher_client
        .get_application_config()
        .await
        .map_err(|error| anyhow!("couldn't get application config: {:?}", error))?;
    log::info!(
        "[timing] get_application_config ({} B) took {:.3} ms",
        application_config.len(),
        t.elapsed().as_secs_f64() * 1e3
    );

    // Decide how to run this workload from the (measured) application config.
    // A CFC wasm workload is selected via the OrchestratorWorkloadConfig
    // envelope; anything else (including arbitrary legacy container config) falls
    // through to the existing runc container path over the original raw bytes.
    let workload_config = crate::wasm_runtime::decode_workload_config(&application_config);
    let wasm_workload = crate::wasm_runtime::wasm_config(&workload_config).cloned();

    // Create the appropriate workload event and add it to the event log. For a
    // wasm workload we build the composition here (unpack + compile + derive the
    // claim) ONCE, before extending the event, so what runs is exactly what is
    // attested (no reload), and hold it to serve after evidence is sent.
    let t = Instant::now();
    let mut attester: A = crate::dice::load_stage1_dice_data()?;
    log::info!("[timing] load_stage1_dice_data took {:.3} ms", t.elapsed().as_secs_f64() * 1e3);
    let mut wasm_composition: Option<crate::wasm_runtime::Composition> = None;
    let mut wasm_session: Option<Arc<crate::confidential_transform::SessionWorkload>> = None;
    let workload_event = if let Some(ref wasm) = wasm_workload {
        // A session-world workload is served over the ConfidentialTransform gRPC
        // API; any other wasm workload runs as a pure-transform composition. Both
        // compile the component(s) and derive the claim ONCE, before extend.
        let claim_bytes = if crate::confidential_transform::is_session_workload(wasm) {
            let t = Instant::now();
            let files = crate::wasm_runtime::unpack_bundle(container_bundle.clone())
                .context("couldn't unpack wasm workload bundle")?;
            log::info!(
                "[timing] unpack_bundle took {:.3} ms",
                t.elapsed().as_secs_f64() * 1e3
            );
            let t = Instant::now();
            let workload = crate::confidential_transform::SessionWorkload::load(wasm, &files)
                .context("couldn't load wasm session workload")?;
            log::info!(
                "[timing] SessionWorkload::load (compile + derive claim) took {:.3} ms",
                t.elapsed().as_secs_f64() * 1e3
            );
            let claim_bytes = workload.claim_bytes().to_vec();
            wasm_session = Some(Arc::new(workload));
            claim_bytes
        } else {
            let composition =
                crate::wasm_runtime::Composition::load_bundle(wasm, container_bundle.clone())
                    .context("couldn't load wasm composition")?;
            let claim_bytes = composition.claim_bytes().to_vec();
            wasm_composition = Some(composition);
            claim_bytes
        };
        oak_containers_attestation::create_wasm_workload_event(
            container_bundle.clone(),
            &application_config[..],
            claim_bytes,
            &instance_public_keys,
        )
    } else {
        oak_containers_attestation::create_container_event(
            container_bundle.clone(),
            &application_config[..],
            &instance_public_keys,
        )
    };
    let encoded_event = workload_event.encode_to_vec();
    // Spawn the `extend`` operation on a separate thread to support cases where we
    // have async attesters.
    let t = Instant::now();
    let attester = tokio::runtime::Handle::current()
        .spawn_blocking(move || {
            attester
                .extend(&encoded_event)
                .context("couldn't add container event to the evidence")?;
            Ok::<A, anyhow::Error>(attester)
        })
        .await??;
    log::info!("[timing] attester.extend (DICE) took {:.3} ms", t.elapsed().as_secs_f64() * 1e3);

    // Add the container event to the DICE chain.
    let t = Instant::now();
    let evidence = {
        #[cfg(feature = "application_keys")]
        {
            // Spawn the `quote` operation on a separate thread to support cases where we
            // have async attesters.
            tokio::runtime::Handle::current()
                .spawn_blocking(move || {
                    let container_layer =
                        oak_containers_attestation::create_container_dice_layer(&workload_event);
                    attester.add_application_keys(
                        container_layer,
                        &instance_public_keys.encryption_public_key,
                        &instance_public_keys.signing_public_key,
                        if let Some(ref group_public_keys) = group_public_keys {
                            Some(&group_public_keys.encryption_public_key)
                        } else {
                            None
                        },
                        None,
                    )
                })
                .await??
        }
        #[cfg(not(feature = "application_keys"))]
        {
            // Spawn the `quote` operation on a separate thread to support cases where we
            // have async attesters.
            tokio::runtime::Handle::current().spawn_blocking(move || attester.quote()).await??
        }
    };
    log::info!(
        "[timing] evidence generation (quote / add_application_keys) took {:.3} ms",
        t.elapsed().as_secs_f64() * 1e3
    );
    // Send the attestation evidence to the Hostlib.
    let t = Instant::now();
    launcher_client
        .send_attestation_evidence(evidence.clone())
        .await
        .map_err(|error| anyhow!("couldn't send attestation evidence: {:?}", error))?;
    log::info!(
        "[timing] send_attestation_evidence took {:.3} ms; total orchestrator startup to \
         evidence-sent {:.3} ms",
        t.elapsed().as_secs_f64() * 1e3,
        t_startup.elapsed().as_secs_f64() * 1e3
    );

    // Confined wasm workload: the composition has been measured and its
    // capability claim is now part of the evidence. Run it directly in the
    // orchestrator (no runc container, so no container IPC server; single wasm
    // TEE, so no group-key provisioning service). The container plumbing below
    // is bypassed.
    if let Some(workload) = wasm_session {
        // Session workload: serve the ConfidentialTransform gRPC API. Bind the
        // socket first, then notify the launcher that the app is ready (the
        // container path does this over IPC via `notify_app_ready`; the wasm
        // path has no container, so the orchestrator does it directly) so the
        // launcher's `get_trusted_app_address` unblocks and proxies to us.
        let addr: std::net::SocketAddr = args
            .confidential_transform_addr
            .parse()
            .context("invalid --confidential_transform_addr")?;
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("couldn't bind ConfidentialTransform on {addr}"))?;
        launcher_client
            .notify_app_ready()
            .await
            .map_err(|error| anyhow!("couldn't notify app ready: {:?}", error))?;
        return crate::confidential_transform::serve_on_listener(
            workload,
            instance_keys.encryption_key.clone(),
            listener,
        )
        .await;
    }
    if let Some(composition) = wasm_composition {
        return composition.serve().await;
    }

    // Request group keys.
    if key_provisioning_role == KeyProvisioningRole::Follower {
        let get_group_keys_response = launcher_client
            .get_group_keys()
            .await
            .map_err(|error| anyhow!("couldn't get group keys: {:?}", error))?;
        let provisioned_group_keys = instance_keys
            .provide_group_keys(get_group_keys_response)
            .context("couldn't provide group keys")?;
        group_keys = Some(Arc::new(provisioned_group_keys));
    }

    if let Some(path) = args.ipc_socket_path.parent() {
        tokio::fs::create_dir_all(path).await?;
    }

    let endorsements = launcher_client
        .get_endorsements()
        .await
        .map_err(|e| anyhow!("coudln't get endorsements from launcher: {e:?}"))?;

    let (orchestrator_server, crypto_server) = crate::ipc_server::create_services(
        evidence,
        endorsements,
        instance_keys,
        group_keys.clone().context("group keys were not provisioned")?,
        application_config,
        launcher_client,
    );

    // Start application and gRPC servers.
    let user = nix::unistd::User::from_name(&args.runtime_user)
        .context(format!("error resolving user {}", args.runtime_user))?
        .context(format!("user `{}` not found", args.runtime_user))?;
    let cancellation_token = CancellationToken::new();
    tokio::try_join!(
        crate::ipc_server::server(
            &args.ipc_socket_path,
            orchestrator_server,
            crypto_server,
            cancellation_token.clone(),
        ),
        crate::key_provisioning::create(
            &args.orchestrator_addr,
            group_keys.context("group keys were not provisioned")?,
            cancellation_token.clone(),
        ),
        crate::container_runtime::run(
            container_bundle,
            &args.container_dir,
            user.uid,
            user.gid,
            &args.ipc_socket_path,
            cancellation_token,
        ),
    )?;

    Ok(())
}
