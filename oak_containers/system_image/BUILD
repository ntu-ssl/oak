#
# Copyright 2024 The Project Oak Authors
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

load("@rules_pkg//pkg:mappings.bzl", "pkg_attributes", "pkg_files")
load("@rules_pkg//pkg:tar.bzl", "pkg_tar")
load("//bazel/tools/xz:xz.bzl", "xz_compress")

package(
    default_visibility = ["//:internal"],
    licenses = ["notice"],
)

pkg_files(
    name = "orchestrator_files",
    srcs = [
        "//oak_containers/orchestrator_bin:bin/oak_containers_orchestrator",
    ],
    attributes = pkg_attributes(
        mode = "0744",
    ),
    strip_prefix = "/oak_containers/orchestrator_bin/bin",
)

pkg_files(
    name = "syslogd_files",
    srcs = [
        "//oak_containers/syslogd",
    ],
    attributes = pkg_attributes(
        mode = "0744",
    ),
    strip_prefix = "/oak_containers/syslogd",
)

pkg_files(
    name = "agent_files",
    srcs = [
        "//oak_containers/agent:bin/oak_containers_agent",
    ],
    attributes = pkg_attributes(
        mode = "0744",
    ),
    strip_prefix = "/oak_containers/agent/bin",
)

pkg_tar(
    name = "rust_bins_tar",
    srcs = [
        ":agent_files",
        ":orchestrator_files",
        ":syslogd_files",
    ],
    package_dir = "/usr/bin",
)

# Debug/config overlay applied on top of the prebuilt base image (which is a pinned,
# http_file-fetched tarball -- edits under base/files/ do NOT rebuild it; only a base
# image rebuild + repin would). Files here are added by Bazel on every system image
# build. The journald drop-in sorts after the base's `override.conf`, so its keys win.
pkg_files(
    name = "overlay_files",
    srcs = ["overlay/etc/systemd/journald.conf.d/zz-debug-journal.conf"],
    prefix = "/etc/systemd/journald.conf.d",
    strip_prefix = "overlay/etc/systemd/journald.conf.d",
)

pkg_tar(
    name = "overlay_tar",
    srcs = [":overlay_files"],
)

pkg_tar(
    name = "oak_containers_system_image_tar",
    deps = [
        ":rust_bins_tar",
        "@oak_containers_system_image_base//file:base-image.tar.xz",
        # Last so its files override same-path entries from the base image.
        ":overlay_tar",
    ],
)

xz_compress(
    name = "oak_containers_system_image",
    out = "oak_containers_system_image.tar.xz",
    target = ":oak_containers_system_image_tar",
)

pkg_tar(
    name = "oak_containers_nvidia_system_image_tar",
    deps = [
        ":rust_bins_tar",
        "@oak_containers_nvidia_system_image_base//file:nvidia-base-image.tar.xz",
    ],
)

xz_compress(
    name = "oak_containers_nvidia_system_image",
    out = "oak_containers_nvidia_system_image.tar.xz",
    target = ":oak_containers_nvidia_system_image_tar",
)
