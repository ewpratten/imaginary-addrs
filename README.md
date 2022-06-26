# Imaginary IPv6 Addresses
[![Build](https://github.com/Ewpratten/imaginary-addrs/actions/workflows/build.yml/badge.svg)](https://github.com/Ewpratten/imaginary-addrs/actions/workflows/build.yml)
[![Clippy](https://github.com/Ewpratten/imaginary-addrs/actions/workflows/clippy.yml/badge.svg)](https://github.com/Ewpratten/imaginary-addrs/actions/workflows/clippy.yml)
[![Audit](https://github.com/Ewpratten/imaginary-addrs/actions/workflows/audit.yml/badge.svg)](https://github.com/Ewpratten/imaginary-addrs/actions/workflows/audit.yml)

This repository contains the fake traceroute server used in my "[Rickrolling the internet](https://va3zza.com/blog/rickrolling-the-internet/)" project.

## Usage

```text
imaginary-addrs 0.1.0
Evan Pratten <ewpratten@gmail.com>
A utility for accepting traceroute on a whole /112 address block without 65 thousand hosts

USAGE:
    imaginary-addrs --interface <INTERFACE> --network <NETWORK>

OPTIONS:
    -h, --help                     Print help information
    -i, --interface <INTERFACE>    Name of the tunnel to bring up
    -n, --network <NETWORK>        The network to operate with
    -V, --version                  Print version information
```

Make sure to run this tool with elevated privileges (aka: `sudo`).

Once running, a new interface will be up on your host, and running `mtr` against any of its addresses will immediately resolve them and all numbers below.

See [my blog post](https://va3zza.com/blog/rickrolling-the-internet/) for more info.
