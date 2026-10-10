# Credits and provenance

This is a fork of [runetfreedom/discord-voice-proxy](https://github.com/runetfreedom/discord-voice-proxy).
The original Discord loader and installer history is retained.

The SOCKS5 wrapper is vendored from
[runetfreedom/force-proxy](https://github.com/runetfreedom/force-proxy), rather
than requiring a second checkout. Its license and original README are retained
under `force-proxy/`.

Starting revisions:

- discord-voice-proxy: `ad909a68a5bc2691622b1ef9ec9b687ba9a65c04`
- force-proxy: `00ba992fc150f4ada7c4dccf7d2c49c9eab6ff83`

Fork changes: Cloudflare DNS over HTTPS through SOCKS5 for hooked Winsock
resolvers; cached DNS answers and parser validation; automatic Chromium
SOCKS5 configuration; an x64 installer that embeds the payload and runtime;
and a single-repository CMake build.

Both upstream projects use GPL-3.0. Their license texts are preserved. Bundled
dependency notices are in `licenses/`.
