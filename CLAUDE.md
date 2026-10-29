# Notes for Claude

## The command line has steghide's syntax

ScatterSteg competes with steghide, so its command line uses steghide's commands and option names for every feature ScatterSteg has: a steghide user should only have to type `scattersteg` instead of `steghide`. The commands are `embed`, `extract`, `info`, `encinfo`, `version`, `license` and `help` (each also as `--embed` and so on); the options are `-ef`, `-cf`, `-sf`, `-xf`, `-z`, `-Z`, `-N`, `-f`, `-q`, `-v`, with steghide's long forms (`--embedfile`, ...).

- **Syntax only, never steghide's text.** Messages, prompts and help text are ScatterSteg's own wording. Don't copy or paraphrase steghide's.
- **New features:** if steghide has an option or command for the same thing, use its name and meaning. If not, pick a name that doesn't clash with one of steghide's. ScatterSteg's own extras so far: the `passphrase` command.
- **Deliberate differences, not bugs** (the README's "Coming from steghide" lists them for users):
  - `-p <passphrase>` is refused, with an explanation: the passphrase is always typed at the prompt, never on the command line where `ps` and shell history would show it. The owner decided this; don't add `-p`.
  - `-e` and `-K` are refused: the encryption is fixed (XSalsa20-Poly1305) and every message is authenticated.
  - `-cf -` and `-sf -` (cover from stdin, output to stdout) aren't supported.
  - An existing output file is refused unless `-f`; there is no yes/no prompt.
  - `info <image>` reports whether the image can be a cover, and its capacity. It doesn't look for a message: nothing can, without the passphrase.
  - Messages are always byte-exact (no newline added or removed).
- **Both front ends:** `main.c` (C) and `rust/src/main.rs` (Rust) must behave identically, wording included. `tests/test_cli.py` runs against each (`SCATTERSTEG=<binary>`).
