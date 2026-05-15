# Console Client

Interactive Rust console client for the messenger workspace.

Features:

- registration (email+phone, email-only, phone-only)
- authorization/login
- chat websocket connection
- local chat list with unread counters
- chat history requests
- sending messages and mark_read actions
- profile view and profile editing

## Config

File: `console-client/config.toml`

Current defaults:

- auth: `http://121.127.37.252:2131`
- chat: `ws://121.127.37.252:3121/ws`

## Run

From workspace root:

```bash
cargo run -p console-client
```

Make sure `auth-service` and `chat-service` are running and reachable from these addresses.
