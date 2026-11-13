# Fuzzing

Coverage-guided fuzzing of the response parser and of the coroutines reading a response, with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer). Two targets, each with its own oracle.

The `parse` target feeds arbitrary bytes to `ManagesieveResponse::parse`. Its oracle is that whatever a server sends, the parser answers a response, an incomplete signal or a typed error, never a panic, and that a response it answers holds together: the bytes it consumed lie within the buffer, no string it carries is longer than them, it renders, and the same bytes parse into the same response again.

The `read` target splits arbitrary bytes into arbitrary reads, follows them with EOF, and feeds them to `ManagesieveResponseRead` and to the challenge reader of `ManagesieveAuthenticate`. It holds three things. Neither reader panics, nor asks for a read once EOF was reported. The splits change nothing: after each read, `ManagesieveResponseRead` stands exactly where `ManagesieveResponse::parse` stands on the bytes fed so far, waiting, failing with the same error or complete with the same response and the same trailing bytes. And the splits cost nothing: a counting allocator measures what each reader allocates, which stays under 4096 bytes plus 512 per byte fed, however many reads carried them. A reader that starts over at each read builds its tokens again each time and leaves that bound within a hundred bytes of input, which is what the bound is there to catch.

cargo-fuzz needs a nightly toolchain, which the `fuzz` devShell of the repository flake carries along with cargo-fuzz itself. Bound a run with the libFuzzer flags after the `--` separator:

```sh
nix develop .#fuzz --command bash -c "cargo fuzz run parse -- -max_total_time=60"
nix develop .#fuzz --command bash -c "cargo fuzz run read -- -max_total_time=60"
```

New interesting inputs land in fuzz/corpus and crashes in fuzz/artifacts, one folder per target (both gitignored), from where a crash is replayed with `cargo fuzz run <target> fuzz/artifacts/<target>/<file>`.
