<table align="center">
  <tr>
    <th width="86">
      <img src="./assets/logo.svg" alt="µLB logo" width="64" align="left" />
    </th>
    <th width="360" align="left">µLB (pronounced "micro LB") is a lightweight, high-performance HTTP/1 load balancer powered by eBPF</th>
  </tr>
</table>

<br />

## Prerequisites

- stable rust toolchains: `rustup toolchain install stable`
- nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
- bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build

```shell
cargo run --release
```

## License

With the exception of eBPF code, `ulb` is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2

## AI Usage Policy

See [AI Usage Disclosure](AI_POLICY.md) for details on the limited use of LLMs in `µLB`.
