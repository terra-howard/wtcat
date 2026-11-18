# Models

TLA+ models of designs with shared state, checked by TLC before the design is built
([decision 0032](../docs/decisions/0032-model-checking-designs.md)). Each directory holds one model and its
configurations. The measurements record each configuration's predicted and actual outcome.

## Running TLC

TLC needs Java 11 or later and `tla2tools.jar` from <https://github.com/tlaplus/tlaplus/releases>. The runs recorded
so far used release v1.7.4 (`tla2tools.jar`, 2,274,532 bytes, SHA-256
`936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`, computed on download, since the release
publishes no checksum) with OpenJDK 21. From a model's directory:

```
java -XX:+UseParallelGC -cp /path/to/tla2tools.jar tlc2.TLC -deadlock -workers 2 -config local.cfg ConnectionReplay.tla
```

`-deadlock` turns off TLC's deadlock check. These models describe systems that may simply stop, for example once
every token has expired, and stopping is not an error.

## connectionreplay

Connection-scoped replay for CAT over MOQT: a `catreplay` 1 token accepted on one connection only, across two
relays. `local.cfg` (a store per relay) and `shared-nonatomic.cfg` (one store, a lookup then a write) are expected
to violate `OneConnection`, and `shared-atomic.cfg` to keep it. Its invariant is carried into Go by
`TestCatreplayConcurrentUseAcceptsOnce` in `cat/replay_test.go`.
