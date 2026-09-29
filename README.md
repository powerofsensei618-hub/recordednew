# recordednew

HLS / recorded video player + proxy (Flask).

- `GET /play?v=<url-encoded video url>` -> player page
- `GET /proxy?u=<url>` -> internal proxy (m3u8 rewrite + CloudFront signed-query forward)
- `GET /health`

Deploy on Render (Docker). Port `$PORT` (default 10000).
Generator page (`index.html`) ka `PLAYER_BASE` isi service ke URL par set karna hai.
