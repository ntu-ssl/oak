#
# Copyright 2026 Confidential Federated Compute Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

load("@rules_rust//cargo:defs.bzl", "cargo_build_script")
load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_library", "rust_test")

package(
    default_visibility = ["//visibility:public"],
    licenses = ["notice"],
)

# The committed component fixtures, exposed so other packages (e.g. the
# orchestrator's wasm_runtime integration test) can consume them as runfiles.
filegroup(
    name = "testdata_wasm",
    srcs = glob(
        ["testdata/*.wasm"],
        allow_empty = True,
    ),
    visibility = ["//visibility:public"],
)

cargo_build_script(
    name = "build",
    srcs = ["build.rs"],
    build_script_env = {
        "PROTOC": "$(execpath @com_google_protobuf//:protoc)",
    },
    data = [
        "proto/wasm_capability.proto",
        "proto/wasm_workload_config.proto",
    ],
    tools = ["@com_google_protobuf//:protoc"],
    deps = ["@oak_crates_index//:prost-build"],
)

rust_library(
    name = "cfc_wasm_capability",
    srcs = glob(["src/**/*.rs"]),
    proc_macro_deps = ["@oak_crates_index//:prost-derive"],
    deps = [
        ":build",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:prost",
        "@oak_crates_index//:sha2",
        "@oak_crates_index//:wasmtime",
    ],
)

rust_test(
    name = "cfc_wasm_capability_test",
    crate = ":cfc_wasm_capability",
)

# Integration tests that run derivation over the real toy component fixtures.
# The .wasm files are embedded via include_bytes! (compile_data), so this target
# only compiles once testdata/guest/build.sh has produced them.
rust_test(
    name = "fixtures_test",
    srcs = ["tests/fixtures.rs"],
    compile_data = glob(
        ["testdata/*.wasm"],
        allow_empty = True,
    ),
    deps = [":cfc_wasm_capability"],
)

# Phase 1a de-risk binary: introspect + derive + run the toy components on the
# host. `bazel run //cfc_wasm_capability:cap_host_selftest`.
rust_binary(
    name = "cap_host_selftest",
    srcs = ["selftest/cap_host_selftest.rs"],
    compile_data = glob(
        ["testdata/*.wasm"],
        allow_empty = True,
    ),
    deps = [
        ":cfc_wasm_capability",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:wasmtime",
    ],
)
