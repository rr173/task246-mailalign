#!/usr/bin/env bash
set -euo pipefail

image_name="${1:-task246-mailalign-benzhi}"
platform="${2:-linux/amd64}"

docker build --platform "$platform" -f benzhi.Dockerfile -t "$image_name" .
echo "Docker image '$image_name' built successfully for $platform"
