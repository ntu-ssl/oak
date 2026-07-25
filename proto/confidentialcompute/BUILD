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

# Vendored copy of federated-compute's
# fcp/protos/confidentialcompute/confidential_transform.proto, kept
# wire-compatible (identical package and field numbers) so the oak orchestrator
# can host the ConfidentialTransform service. Vendored because the dependency
# runs fcp -> oak (the proto imports oak's proto/crypto/crypto.proto), so oak
# cannot depend back on federated-compute.

load("@com_google_protobuf//bazel:proto_library.bzl", "proto_library")

package(
    default_visibility = ["//:default_visibility"],
    licenses = ["notice"],
)

proto_library(
    name = "confidential_transform_proto",
    srcs = ["confidential_transform.proto"],
    deps = [
        "//proto/crypto:crypto_proto",
        "//third_party/google/rpc:status_proto",
        "@com_google_protobuf//:any_proto",
    ],
)
