# Renesas RL78 support for probe-rs

The COM-port debugger found on Renesas Fast Prototyping Boards (an FT232R wired to TOOL0 and
RESET), and RL78 target descriptions. The RL78 architecture itself lives in `probe-rs`, under
`architecture/rl78`.

Register the plugin before using probe-rs:

```rust
fn main() {
    probe_rs_rl78::register_plugin();
}
```

A part with a security ID other than ten `00H` bytes needs it in `PROBE_RS_RL78_SECURITY_ID`,
as 20 hex digits.
