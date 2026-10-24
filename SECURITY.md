# Security policy

## Reporting a vulnerability

Please **don't open a public issue** for a security problem. Report it privately through GitHub: on the repository's **Security** tab, choose **Report a vulnerability**. Include what you found, how to reproduce it (a sample image is ideal), and the commit or release you tested.

You can expect an acknowledgement within a week, and a fix or a plan within 30 days for anything confirmed. Reporters are credited in the fix's commit message unless they'd rather not be.

## What counts

Anything that breaks a claim in [THREAT_MODEL.md](THREAT_MODEL.md), for example:

- reading a message, or learning anything about it, without the passphrase;
- testing passphrase guesses more cheaply than one Argon2id run each;
- a modified image decoding to a wrong message instead of failing;
- an input file that causes memory corruption, a crash, or unbounded memory or time;
- secrets left in memory, swap, core dumps or files where the threat model says they aren't;
- a detector, published or your own, that reliably tells ScatterSteg output from clean images at payloads the README presents as low-risk. This is a security issue here, not just a research result.

Things the threat model lists as non-goals (robustness to recompression, deniability under coercion, comparison against the original cover) aren't vulnerabilities, but suggestions are welcome as ordinary issues.

## Supported versions

Only the latest release and `main` get fixes. The image format is versioned (currently v4) and older formats stay readable, so upgrading never strands a message.
