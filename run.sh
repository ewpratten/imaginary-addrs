#! /bin/bash
set -ex

cargo build
export RUST_BACKTRACE=1
sudo -E ./target/debug/imaginary-addrs -i rickroll0 -n fc00:c01c::/64