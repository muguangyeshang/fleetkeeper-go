# fleetkeeper-go

Go port of [fleetkeeper](https://github.com/muguangyeshang/fleetkeeper)'s
two hardest modules — service **discovery** and **guarded self-healing** —
written to demonstrate the same design in a compiled, dependency-free
systems language.

## Why a port, and what it shows

Same semantics as the Python original, different machinery:

| Concern | Python (fleetkeeper) | Go (this repo) |
|---|---|---|
| Bounded concurrent probes | `ThreadPoolExecutor` + semaphore | goroutines + channel (`sem := make(chan struct{}, workers)`) |
| HTTP probe | `http.client` | hand-written HTTP/1.0 over `net.DialTimeout` — no dependency, no subprocess |
| Classification | ordered signature table | same table, statically typed structs |
| Result types | dicts, checked at runtime | structs, checked at compile time |

## Status

- `internal/discover` — signature table (Ollama / OpenAI-compatible /
  ComfyUI / any-HTTP fallback), existing-port marking, 64 KiB body cap,
  bounded worker pool. 6 tests, real loopback sockets.
- `internal/watchdog` — sweep loop with the four brakes: per-port
  cooldown (survives green sweeps and process restarts by design),
  WAN gate (network down ⇒ record, never heal), pause markers
  (`<port>.paused`), consecutive-down threshold. 5 tests.
- `cmd/fleetkeeper-go` — CLI: `-mode discover` prints JSON candidates,
  `-mode guard` loops sweeps. Recovery-command wiring (PID-verified
  restarts) lands next; the heal hook returns an explicit error instead
  of a silent no-op until then.

## Build & run

```
go build -o fleetkeeper-go.exe ./cmd/fleetkeeper-go
./fleetkeeper-go.exe -ports 11434,4002,8000 -existing 4002
./fleetkeeper-go.exe -ports 4002 -mode guard -cooldown 180s -threshold 2
```

## Tests

```
go test -v ./...
```

11 tests, all against real loopback sockets — the Python suite's rule
(mocks hide real bugs) carries over.

## License

MIT
