use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use keyring::Entry;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout};
use tokio_tungstenite::{connect_async, tungstenite::Message};

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const BLUE: &str = "\x1b[34m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const CYAN: &str = "\x1b[36m";

#[derive(Debug, Deserialize, Clone)]
struct Config {
    auth: AuthConfig,
    chat: ChatConfig,
    #[serde(default)]
    session: SessionConfig,
    #[serde(default)]
    ui: UiConfig,
}

#[derive(Debug, Deserialize, Clone)]
struct AuthConfig {
    base_url: String,
}

#[derive(Debug, Deserialize, Clone)]
struct ChatConfig {
    ws_url: String,
    #[serde(default = "default_history_limit")]
    default_history_limit: usize,
}

#[derive(Debug, Deserialize, Clone)]
struct SessionConfig {
    #[serde(default = "default_lifetime")]
    default_lifetime_seconds: i32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            default_lifetime_seconds: 3600,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
struct UiConfig {
    #[serde(default = "default_clear_menu")]
    clear_screen_on_menu: bool,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            clear_screen_on_menu: true,
        }
    }
}

fn default_lifetime() -> i32 {
    3600
}

fn default_history_limit() -> usize {
    50
}

fn default_clear_menu() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct SessionUserInfo {
    uuid: Option<String>,
    username: String,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct UserProfile {
    username: String,
    first_name: String,
    last_name: String,
    date_of_birth: String,
    additional_info: String,
    pub uuid: Option<String>,
}

#[derive(Debug, Serialize)]
struct LoginRequest {
    login_type: String,
    login_details: String,
    password: String,
    live_time: i32,
}

#[derive(Debug, Serialize)]
struct SessionPayload {
    session_tocken: String,
}

#[derive(Debug, Serialize)]
struct ChangeAnyThingPayload {
    session_tocken: String,
    new_value: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct StoredMessage {
    uuid: String,
    sender_id: String,
    receiver_id: String,
    dialog_id: String,
    text: Option<String>,
    file_id: Option<String>,
    created_at: String,
    delivered_at: Option<String>,
    status: i64,
}

#[derive(Debug, Deserialize, Clone)]
struct ConnectionInfo {
    number: usize,
    uuid: Option<String>,
    username: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(tag = "action", rename_all = "snake_case")]
enum ClientAction {
    Join {
        session_token: String,
    },
    SendMessage {
        session_token: String,
        receiver_id: String,
        text: Option<String>,
        file_id: Option<String>,
    },
    History {
        session_token: String,
        with_user_id: String,
        limit: Option<usize>,
    },
    MarkRead {
        session_token: String,
        with_user_id: String,
    },
    ListConnections {
        session_token: String,
    },
    Ping {
        session_token: String,
    },
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerEvent {
    Joined {
        user_id: String,
        username: String,
        connection_number: usize,
    },
    Message {
        message: StoredMessage,
    },
    History {
        with_user_id: String,
        messages: Vec<StoredMessage>,
    },
    MarkReadResult {
        with_user_id: String,
        updated: usize,
    },
    ReadReceipt {
        by_user_id: String,
        updated: usize,
    },
    Connections {
        connections: Vec<ConnectionInfo>,
    },
    Pong,
    Error {
        message: String,
    },
}

#[derive(Clone)]
struct AuthClient {
    http: reqwest::Client,
    base_url: String,
}

impl AuthClient {
    fn new(base_url: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url,
        }
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}/{}", self.base_url.trim_end_matches('/'), path)
    }

    async fn register_full(
        &self,
        username: &str,
        password: &str,
        email: &str,
        phone_number: &str,
    ) -> Result<(), String> {
        let response = self
            .http
            .get(self.endpoint("adduser"))
            .query(&[
                ("username", username),
                ("password", password),
                ("email", email),
                ("phone_number", phone_number),
            ])
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        ensure_ok_plain(response).await
    }

    async fn register_email_only(
        &self,
        username: &str,
        password: &str,
        email: &str,
    ) -> Result<(), String> {
        let response = self
            .http
            .get(self.endpoint("adduserwithoutphone"))
            .query(&[("username", username), ("password", password), ("email", email)])
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        ensure_ok_plain(response).await
    }

    async fn register_phone_only(
        &self,
        username: &str,
        password: &str,
        phone_number: &str,
    ) -> Result<(), String> {
        let response = self
            .http
            .post(self.endpoint("adduserwithoutemail"))
            .json(&serde_json::json!({
                "username": username,
                "password": password,
                "phone_number": phone_number,
            }))
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        ensure_ok_plain(response).await
    }

    async fn login(
        &self,
        login_type: &str,
        login_details: &str,
        password: &str,
        live_time: i32,
    ) -> Result<String, String> {
        let body = LoginRequest {
            login_type: login_type.to_string(),
            login_details: login_details.to_string(),
            password: password.to_string(),
            live_time,
        };

        let response = self
            .http
            .post(self.endpoint("login"))
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        parse_plain_success(response).await
    }

    async fn session_user_info(&self, session_tocken: &str) -> Result<SessionUserInfo, String> {
        let response = self
            .http
            .post(self.endpoint("sessionuserinfo"))
            .json(&SessionPayload {
                session_tocken: session_tocken.to_string(),
            })
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        parse_json_success(response).await
    }

    async fn get_user_info(&self, session_tocken: &str, username: &str) -> Result<UserProfile, String> {
        let response = self
            .http
            .get(self.endpoint("getuserinfo"))
            .query(&[("session_tocken", session_tocken), ("username", username)])
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        parse_json_success(response).await
    }

    async fn change_username(&self, session_tocken: &str, new_value: &str) -> Result<(), String> {
        let response = self
            .http
            .get(self.endpoint("changeusername"))
            .query(&[("session_tocken", session_tocken), ("new_value", new_value)])
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        ensure_ok_plain(response).await
    }

    async fn change_first_name(&self, session_tocken: &str, new_value: &str) -> Result<(), String> {
        let response = self
            .http
            .post(self.endpoint("changefirstname"))
            .json(&ChangeAnyThingPayload {
                session_tocken: session_tocken.to_string(),
                new_value: new_value.to_string(),
            })
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        ensure_ok_plain(response).await
    }

    async fn change_last_name(&self, session_tocken: &str, new_value: &str) -> Result<(), String> {
        let response = self
            .http
            .post(self.endpoint("changelastname"))
            .json(&ChangeAnyThingPayload {
                session_tocken: session_tocken.to_string(),
                new_value: new_value.to_string(),
            })
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        ensure_ok_plain(response).await
    }

    async fn change_birth_date(&self, session_tocken: &str, new_value: &str) -> Result<(), String> {
        let response = self
            .http
            .post(self.endpoint("changedateofbirth"))
            .json(&ChangeAnyThingPayload {
                session_tocken: session_tocken.to_string(),
                new_value: new_value.to_string(),
            })
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        ensure_ok_plain(response).await
    }

    async fn change_additional_info(
        &self,
        session_tocken: &str,
        new_value: &str,
    ) -> Result<(), String> {
        let response = self
            .http
            .post(self.endpoint("changeadditionalinfo"))
            .json(&ChangeAnyThingPayload {
                session_tocken: session_tocken.to_string(),
                new_value: new_value.to_string(),
            })
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        ensure_ok_plain(response).await
    }

    async fn set_online(&self, session_tocken: &str) -> Result<(), String> {
        let response = self
            .http
            .get(self.endpoint("online"))
            .query(&[("session_tocken", session_tocken)])
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        ensure_ok_plain(response).await
    }

    async fn set_offline(&self, session_tocken: &str) -> Result<(), String> {
        let response = self
            .http
            .get(self.endpoint("offline"))
            .query(&[("session_tocken", session_tocken)])
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        ensure_ok_plain(response).await
    }
}

struct WsSession {
    outgoing_tx: mpsc::UnboundedSender<ClientAction>,
    inbound_rx: mpsc::UnboundedReceiver<ServerEvent>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ChatEntry {
    user_id: String,
    label: String,
    unread: usize,
}

fn get_chats_file() -> PathBuf {
    if let Some(config_dir) = dirs::config_dir() {
        config_dir.join("messenger-client").join("chats.json")
    } else {
        PathBuf::from(".messenger-chats.json")
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ChatsList {
    chats: Vec<ChatEntry>,
}

fn load_chats_list() -> Vec<ChatEntry> {
    let chats_file = get_chats_file();
    if let Ok(content) = fs::read_to_string(&chats_file) {
        if let Ok(list) = serde_json::from_str::<ChatsList>(&content) {
            return list.chats;
        }
    }
    Vec::new()
}

fn save_chats_list(chats: &Vec<ChatEntry>) -> Result<(), String> {
    let chats_file = get_chats_file();
    if let Some(parent) = chats_file.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create config directory: {e}"))?;
    }
    let list = ChatsList { chats: chats.clone() };
    let json = serde_json::to_string_pretty(&list).map_err(|e| format!("JSON serialization failed: {e}"))?;
    fs::write(&chats_file, json).map_err(|e| format!("Failed to save chats list: {e}"))
}

// Session management functions
fn save_session(username: &str, session_token: &str) -> Result<(), String> {
    match Entry::new("messenger-console-client", username) {
        Ok(entry) => entry
            .set_password(session_token)
            .map_err(|e| format!("Failed to save session: {e}")),
        Err(e) => Err(format!("Keyring error: {e}")),
    }
}

fn load_session(username: &str) -> Option<String> {
    match Entry::new("messenger-console-client", username) {
        Ok(entry) => entry.get_password().ok(),
        Err(_) => None,
    }
}

fn delete_session(username: &str) -> Result<(), String> {
    match Entry::new("messenger-console-client", username) {
        Ok(entry) => entry
            .delete_password()
            .map_err(|e| format!("Failed to delete session: {e}")),
        Err(e) => Err(format!("Keyring error: {e}")),
    }
}

fn get_sessions_file() -> PathBuf {
    if let Some(config_dir) = dirs::config_dir() {
        config_dir.join("messenger-client").join("sessions.json")
    } else {
        PathBuf::from(".messenger-sessions.json")
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SessionsList {
    usernames: Vec<String>,
}

fn load_sessions_list() -> Vec<String> {
    let sessions_file = get_sessions_file();
    
    if let Ok(content) = fs::read_to_string(&sessions_file) {
        if let Ok(list) = serde_json::from_str::<SessionsList>(&content) {
            return list.usernames;
        }
    }
    
    Vec::new()
}

fn add_to_sessions_list(username: &str) -> Result<(), String> {
    let sessions_file = get_sessions_file();
    
    // Create parent dirs if needed
    if let Some(parent) = sessions_file.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory: {e}"))?;
    }
    
    let mut sessions = load_sessions_list();
    if !sessions.contains(&username.to_string()) {
        sessions.push(username.to_string());
    }
    
    let list = SessionsList { usernames: sessions };
    let json = serde_json::to_string_pretty(&list)
        .map_err(|e| format!("JSON serialization failed: {e}"))?;
    
    fs::write(&sessions_file, json)
        .map_err(|e| format!("Failed to save sessions list: {e}"))
}

fn remove_from_sessions_list(username: &str) -> Result<(), String> {
    let sessions_file = get_sessions_file();
    let mut sessions = load_sessions_list();
    
    sessions.retain(|u| u != username);
    
    let list = SessionsList { usernames: sessions };
    let json = serde_json::to_string_pretty(&list)
        .map_err(|e| format!("JSON serialization failed: {e}"))?;
    
    fs::write(&sessions_file, json)
        .map_err(|e| format!("Failed to save sessions list: {e}"))
}

struct App {
    config: Config,
    auth: AuthClient,
    session_token: Option<String>,
    me: Option<SessionUserInfo>,
    ws: Option<WsSession>,
    chats: Vec<ChatEntry>,
    current_username: Option<String>,
}

impl App {
    fn new(config: Config) -> Self {
        Self {
            auth: AuthClient::new(config.auth.base_url.clone()),
            config,
            session_token: None,
            me: None,
            ws: None,
            chats: load_chats_list(),
            current_username: None,
        }
    }

    async fn run(&mut self) {
        loop {
            self.drain_events();
            self.render_main_menu();

            let choice = prompt("Select option");
            match choice.as_str() {
                "1" => self.registration_menu().await,
                "2" => self.login_menu().await,
                "3" => {
                    if let Err(e) = self.connect_chat().await {
                        print_error(&format!("Chat connection failed: {e}"));
                    }
                }
                "4" => self.chat_list_menu().await,
                "5" => self.profile_menu().await,
                "6" => self.ping_chat().await,
                "7" => self.logout().await,
                "8" => self.switch_account_menu().await,
                "0" => {
                    self.safe_offline().await;
                    println!("{}Bye.{}", GREEN, RESET);
                    break;
                }
                _ => print_error("Unknown menu option"),
            }

            wait_enter();
        }
    }

    fn render_main_menu(&self) {
        if self.config.ui.clear_screen_on_menu {
            clear_screen();
        }

        banner();
        println!(
            "{}Main menu{}  {}auth:{} {}  {}ws:{} {}",
            BOLD,
            RESET,
            DIM,
            RESET,
            self.auth.base_url,
            DIM,
            RESET,
            self.config.chat.ws_url
        );

        if let Some(me) = &self.me {
            println!(
                "{}Session:{} user={} ({})",
                CYAN,
                RESET,
                me.username,
                me.uuid.as_deref().unwrap_or("n/a")
            );
        } else {
            println!("{}Session:{} not authorized", YELLOW, RESET);
        }

        println!("{}------------------------------------------------------------{}", DIM, RESET);
        println!("{}1{} Register", BLUE, RESET);
        println!("{}2{} Login", BLUE, RESET);
        println!("{}3{} Connect chat socket", BLUE, RESET);
        println!("{}4{} Chats and history", BLUE, RESET);
        println!("{}5{} Profiles", BLUE, RESET);
        println!("{}6{} Ping chat socket", BLUE, RESET);
        println!("{}7{} Logout", BLUE, RESET);
        println!("{}8{} Switch account", BLUE, RESET);
        println!("{}0{} Exit", BLUE, RESET);
    }

    async fn ping_chat(&mut self) {
        if self.require_login().is_err() {
            return;
        }

        if self.ws.is_none()
            && let Err(e) = self.connect_chat().await
        {
            print_error(&format!("Cannot ping chat: {e}"));
            return;
        }

        let Some(session_token) = self.session_token.clone() else {
            print_error("Please login first");
            return;
        };

        if let Err(e) = self.send_ws_action(ClientAction::Ping { session_token }) {
            print_error(&format!("Ping failed: {e}"));
            return;
        }

        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let evt = {
                let ws = match self.ws.as_mut() {
                    Some(ws) => ws,
                    None => {
                        print_error("WebSocket not connected");
                        return;
                    }
                };

                match timeout(remaining, ws.inbound_rx.recv()).await {
                    Ok(Some(evt)) => Some(evt),
                    Ok(None) => None,
                    Err(_) => None,
                }
            };

            let Some(evt) = evt else {
                continue;
            };

            match evt {
                ServerEvent::Pong => {
                    print_ok("Pong received");
                    return;
                }
                other => self.handle_server_event(other),
            }
        }

        print_error("Ping timeout");
    }

    async fn registration_menu(&mut self) {
        title("Registration");
        println!("1) Email + phone");
        println!("2) Email only");
        println!("3) Phone only");
        println!("0) Back");

        match prompt("Registration mode").as_str() {
            "1" => {
                let username = prompt_required("username");
                let password = prompt_required("password");
                let email = prompt_required("email");
                let phone = prompt_required("phone_number (+79991234567)");
                match self
                    .auth
                    .register_full(&username, &password, &email, &phone)
                    .await
                {
                    Ok(_) => print_ok("User registered"),
                    Err(e) => print_error(&format!("Register failed: {e}")),
                }
            }
            "2" => {
                let username = prompt_required("username");
                let password = prompt_required("password");
                let email = prompt_required("email");
                match self
                    .auth
                    .register_email_only(&username, &password, &email)
                    .await
                {
                    Ok(_) => print_ok("User registered"),
                    Err(e) => print_error(&format!("Register failed: {e}")),
                }
            }
            "3" => {
                let username = prompt_required("username");
                let password = prompt_required("password");
                let phone = prompt_required("phone_number (+79991234567)");
                match self
                    .auth
                    .register_phone_only(&username, &password, &phone)
                    .await
                {
                    Ok(_) => print_ok("User registered"),
                    Err(e) => print_error(&format!("Register failed: {e}")),
                }
            }
            _ => {}
        }
    }

    async fn login_menu(&mut self) {
        title("Login");

        let mode_input = prompt("Mode (email/phone)");
        let mode = if mode_input.eq_ignore_ascii_case("phone") {
            "phone"
        } else {
            "email"
        };

        let login_details = if mode == "email" {
            prompt_required("email")
        } else {
            prompt_required("phone")
        };

        let password = prompt_required("password");
        let live_time = self.config.session.default_lifetime_seconds;

        let token = match self
            .auth
            .login(mode, &login_details, &password, live_time)
            .await
        {
            Ok(token) => token,
            Err(e) => {
                print_error(&format!("Login failed: {e}"));
                return;
            }
        };

        let me = match self.auth.session_user_info(&token).await {
            Ok(me) => me,
            Err(e) => {
                print_error(&format!("Session resolve failed: {e}"));
                return;
            }
        };

        self.session_token = Some(token.clone());
        self.me = Some(me.clone());
        self.current_username = Some(me.username.clone());

        // Save session token to keyring
        if let Err(e) = save_session(&me.username, &token) {
            print_error(&format!("Failed to save session: {e}"));
        } else {
            // Also add to saved sessions list
            if let Err(e) = add_to_sessions_list(&me.username) {
                print_error(&format!("Failed to add to sessions list: {e}"));
            } else {
                print_ok(&format!("Session saved for: {}", me.username));
            }
        }

        let _ = self.auth.set_online(&token).await;
        print_ok(&format!("Login successful: {} ({})", me.username, me.uuid.as_deref().unwrap_or("n/a")));

        if let Err(e) = self.connect_chat().await {
            print_error(&format!("Chat connection failed: {e}"));
        }
    }

    async fn connect_chat(&mut self) -> Result<(), String> {
        if self.ws.is_some() {
            print_ok("Chat socket is already connected");
            return Ok(());
        }

        let session = self
            .session_token
            .clone()
            .ok_or_else(|| "Please login first".to_string())?;

        let ws = connect_ws(&self.config.chat.ws_url, &session).await?;
        self.ws = Some(ws);

        match self.wait_for_join(5).await {
            Ok(()) => {
                print_ok("Connected to chat WebSocket");
                Ok(())
            }
            Err(e) => {
                self.ws = None;
                Err(e)
            }
        }
    }

    async fn wait_for_join(&mut self, seconds: u64) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(seconds);

        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let evt = {
                let ws = self
                    .ws
                    .as_mut()
                    .ok_or_else(|| "WebSocket disconnected".to_string())?;

                match timeout(remaining, ws.inbound_rx.recv()).await {
                    Ok(Some(event)) => Some(event),
                    Ok(None) => return Err("WebSocket closed".to_string()),
                    Err(_) => None,
                }
            };

            let Some(event) = evt else {
                continue;
            };

            match event {
                ServerEvent::Joined {
                    user_id,
                    username,
                    connection_number,
                } => {
                    print_ok(&format!(
                        "Joined as {} ({}) [connection #{}]",
                        username, user_id, connection_number
                    ));
                    return Ok(());
                }
                ServerEvent::Error { message } => {
                    return Err(format!("Join rejected: {message}"));
                }
                other => self.handle_server_event(other),
            }
        }

        Err("Join timeout".to_string())
    }

    async fn chat_list_menu(&mut self) {
        title("Chats");

        if self.require_login().is_err() {
            return;
        }

        if self.ws.is_none() {
            if let Err(e) = self.connect_chat().await {
                print_error(&format!("Cannot open chat menu: {e}"));
                return;
            }
        }

        loop {
            self.drain_events();
            print_chat_list(&self.chats);
            println!("\n1) Add chat by username");
            println!("2) Open chat");
            println!("3) Remove chat");
            println!("4) Online connections");
            println!("0) Back");

            match prompt("Chats menu").as_str() {
                "1" => {
                    let username = prompt_required("target username");
                    let Some(token) = self.session_token.as_deref() else {
                        print_error("Please login first");
                        continue;
                    };

                    match self.auth.get_user_info(token, &username).await {
                        Ok(profile) => {
                            let user_id = profile.uuid.clone().unwrap_or(profile.username.clone());
                            let label = prompt("label (optional)");
                            self.ensure_chat_exists(&user_id, if label.is_empty() { None } else { Some(label) });
                            print_ok(&format!("Chat with {} ({}) added", username, short_id(&user_id)));
                        }
                        Err(e) => print_error(&format!("Failed to resolve username: {e}")),
                    }
                }
                "2" => {
                    if self.chats.is_empty() {
                        print_error("Chat list is empty");
                        continue;
                    }
                    let idx = prompt("chat index").parse::<usize>().unwrap_or(0);
                    if idx == 0 || idx > self.chats.len() {
                        print_error("Invalid index");
                        continue;
                    }
                    self.open_chat(idx - 1).await;
                }
                "3" => {
                    let idx = prompt("chat index to remove").parse::<usize>().unwrap_or(0);
                    if idx == 0 || idx > self.chats.len() {
                        print_error("Invalid index");
                        continue;
                    }
                    self.chats.remove(idx - 1);
                    if let Err(e) = save_chats_list(&self.chats) {
                        print_error(&format!("Failed to save chats: {e}"));
                    }
                    print_ok("Chat removed");
                }
                "4" => {
                    if let Err(e) = self.send_ws_action(ClientAction::ListConnections {
                        session_token: self.session_token.clone().unwrap_or_default(),
                    }) {
                        print_error(&format!("Failed to request list_connections: {e}"));
                    } else {
                        self.wait_and_print_connections().await;
                    }
                }
                "0" => break,
                _ => print_error("Unknown option"),
            }
        }
    }

    async fn open_chat(&mut self, index: usize) {
        let chat = match self.chats.get(index).cloned() {
            Some(value) => value,
            None => {
                print_error("Chat not found");
                return;
            }
        };

        if let Some(current) = self.chats.get_mut(index) {
            current.unread = 0;
            if let Err(e) = save_chats_list(&self.chats) {
                print_error(&format!("Failed to save chats: {e}"));
            }
        }

        loop {
            title(&format!("Chat with {} [{}]", chat.label, chat.user_id));
            self.request_history(&chat.user_id, self.config.chat.default_history_limit)
                .await;

            println!("\n1) Send message");
            println!("2) Refresh history");
            println!("3) Mark as read");
            println!("4) Rename chat label");
            println!("0) Back");

            match prompt("Chat menu").as_str() {
                "1" => {
                    let text = prompt_required("message text");
                    if let Err(e) = self.send_ws_action(ClientAction::SendMessage {
                        session_token: self.session_token.clone().unwrap_or_default(),
                        receiver_id: chat.user_id.clone(),
                        text: Some(text),
                        file_id: None,
                    }) {
                        print_error(&format!("Send failed: {e}"));
                    } else {
                        print_ok("Message sent");
                    }
                }
                "2" => {}
                "3" => {
                    if let Err(e) = self.send_ws_action(ClientAction::MarkRead {
                        session_token: self.session_token.clone().unwrap_or_default(),
                        with_user_id: chat.user_id.clone(),
                    }) {
                        print_error(&format!("Mark read failed: {e}"));
                    } else {
                        print_ok("mark_read sent");
                    }
                }
                "4" => {
                    let new_label = prompt_required("new label");
                    if let Some(current) = self.chats.get_mut(index) {
                        current.label = new_label;
                        if let Err(e) = save_chats_list(&self.chats) {
                            print_error(&format!("Failed to save chats: {e}"));
                        }
                    }
                }
                "0" => break,
                _ => print_error("Unknown option"),
            }

            wait_enter();
        }
    }

    async fn request_history(&mut self, with_user_id: &str, limit: usize) {
        if let Err(e) = self.send_ws_action(ClientAction::History {
            session_token: self.session_token.clone().unwrap_or_default(),
            with_user_id: with_user_id.to_string(),
            limit: Some(limit),
        }) {
            print_error(&format!("History request failed: {e}"));
            return;
        }

        let deadline = Instant::now() + Duration::from_secs(4);
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let next = {
                let ws = match self.ws.as_mut() {
                    Some(ws) => ws,
                    None => {
                        print_error("WebSocket not connected");
                        return;
                    }
                };

                match timeout(remaining, ws.inbound_rx.recv()).await {
                    Ok(Some(evt)) => Some(evt),
                    Ok(None) => None,
                    Err(_) => None,
                }
            };

            let Some(event) = next else {
                continue;
            };

            match event {
                ServerEvent::History {
                    with_user_id: event_user,
                    messages,
                } if event_user == with_user_id => {
                    self.print_history(with_user_id, &messages);
                    return;
                }
                other => self.handle_server_event(other),
            }
        }

        print_error("No history response from server (timeout)");
    }

    fn print_history(&self, with_user_id: &str, messages: &[StoredMessage]) {
        println!(
            "\n{}History{} with {} ({} messages)",
            BOLD,
            RESET,
            with_user_id,
            messages.len()
        );
        println!("{}------------------------------------------------------------{}", DIM, RESET);

        let my_id = self.me.as_ref().and_then(|x| x.uuid.as_deref());
        for msg in messages {
            let direction = if Some(msg.sender_id.as_str()) == my_id {
                "out"
            } else {
                "in "
            };

            let status = match msg.status {
                0 => "pending",
                1 => "delivered",
                2 => "read",
                _ => "unknown",
            };

            let text = msg.text.as_deref().unwrap_or("<empty>");
            println!(
                "[{}] {} {} -> {} | {} | {}",
                msg.created_at, direction, msg.sender_id, msg.receiver_id, status, text
            );
        }

        if messages.is_empty() {
            println!("{}No messages yet.{}", DIM, RESET);
        }
    }

    async fn wait_and_print_connections(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(3);

        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let evt = {
                let ws = match self.ws.as_mut() {
                    Some(ws) => ws,
                    None => {
                        print_error("WebSocket not connected");
                        return;
                    }
                };

                match timeout(remaining, ws.inbound_rx.recv()).await {
                    Ok(Some(evt)) => Some(evt),
                    Ok(None) => None,
                    Err(_) => None,
                }
            };

            let Some(evt) = evt else {
                continue;
            };

            match evt {
                ServerEvent::Connections { connections } => {
                    println!("\n{}Online connections:{}", CYAN, RESET);
                    if connections.is_empty() {
                        println!("  none");
                    } else {
                        for c in connections {
                                println!("  #{} {} ({})", c.number, c.username, c.uuid.as_deref().unwrap_or("n/a"));
                            }
                    }
                    return;
                }
                other => self.handle_server_event(other),
            }
        }

        print_error("No connections response from server");
    }

    async fn profile_menu(&mut self) {
        title("Profiles");

        if self.require_login().is_err() {
            return;
        }

        loop {
            println!("1) My profile");
            println!("2) Find profile by username");
            println!("3) Change first name");
            println!("4) Change last name");
            println!("5) Change date of birth");
            println!("6) Change additional info");
            println!("7) Change username");
            println!("0) Back");

            match prompt("Profiles menu").as_str() {
                "1" => {
                    let Some(token) = self.session_token.as_deref() else {
                        print_error("Please login first");
                        continue;
                    };
                    let Some(me) = self.me.as_ref() else {
                        print_error("Current user is unknown");
                        continue;
                    };

                    match self.auth.get_user_info(token, &me.username).await {
                        Ok(profile) => print_profile(&profile),
                        Err(e) => print_error(&format!("Failed to load profile: {e}")),
                    }
                }
                "2" => {
                    let username = prompt_required("username");
                    let Some(token) = self.session_token.as_deref() else {
                        print_error("Please login first");
                        continue;
                    };
                    match self.auth.get_user_info(token, &username).await {
                        Ok(profile) => print_profile(&profile),
                        Err(e) => print_error(&format!("Failed to load profile: {e}")),
                    }
                }
                "3" => self.change_profile_field("first name").await,
                "4" => self.change_profile_field("last name").await,
                "5" => self.change_profile_field("date of birth").await,
                "6" => self.change_profile_field("additional info").await,
                "7" => self.change_profile_field("username").await,
                "0" => break,
                _ => print_error("Unknown option"),
            }

            wait_enter();
            title("Profiles");
        }
    }

    async fn change_profile_field(&mut self, field: &str) {
        let Some(token) = self.session_token.clone() else {
            print_error("Please login first");
            return;
        };

        let new_value = prompt_required(&format!("new {field}"));
        let result = match field {
            "first name" => self.auth.change_first_name(&token, &new_value).await,
            "last name" => self.auth.change_last_name(&token, &new_value).await,
            "date of birth" => self.auth.change_birth_date(&token, &new_value).await,
            "additional info" => self.auth.change_additional_info(&token, &new_value).await,
            "username" => self.auth.change_username(&token, &new_value).await,
            _ => Err("Unsupported field".to_string()),
        };

        match result {
            Ok(()) => {
                if field == "username"
                    && let Some(me) = self.me.as_mut()
                {
                    me.username = new_value;
                }
                print_ok("Profile updated");
            }
            Err(e) => print_error(&format!("Update failed: {e}")),
        }
    }

    async fn logout(&mut self) {
        self.safe_offline().await;
        
        // Delete session from keyring and sessions list
        if let Some(username) = &self.current_username {
            if let Err(e) = delete_session(username) {
                print_error(&format!("Failed to delete session: {e}"));
            }
            if let Err(e) = remove_from_sessions_list(username) {
                print_error(&format!("Failed to remove from sessions list: {e}"));
            }
        }
        
        self.ws = None;
        self.session_token = None;
        self.me = None;
        self.current_username = None;
        print_ok("Logged out");
    }

    async fn safe_offline(&self) {
        if let Some(token) = self.session_token.as_deref() {
            let _ = self.auth.set_offline(token).await;
        }
    }

    fn require_login(&self) -> Result<(), ()> {
        if self.session_token.is_none() {
            print_error("Please login first");
            Err(())
        } else {
            Ok(())
        }
    }

    fn send_ws_action(&self, action: ClientAction) -> Result<(), String> {
        let ws = self
            .ws
            .as_ref()
            .ok_or_else(|| "WebSocket is not connected".to_string())?;
        ws.outgoing_tx
            .send(action)
            .map_err(|_| "WebSocket channel closed".to_string())
    }

    fn drain_events(&mut self) {
        let mut events = Vec::new();

        if let Some(ws) = self.ws.as_mut() {
            while let Ok(evt) = ws.inbound_rx.try_recv() {
                events.push(evt);
            }
        }

        for event in events {
            self.handle_server_event(event);
        }
    }

    fn handle_server_event(&mut self, event: ServerEvent) {
        match event {
            ServerEvent::Message { message } => {
                let me = self.me.as_ref().and_then(|x| x.uuid.clone()).unwrap_or_default();
                let peer_id = if message.sender_id == me {
                    message.receiver_id.clone()
                } else {
                    message.sender_id.clone()
                };

                let from_peer = message.sender_id != me;
                self.ensure_chat_exists(&peer_id, None);
                if from_peer
                    && let Some(chat) = self.chats.iter_mut().find(|c| c.user_id == peer_id)
                {
                    chat.unread = chat.unread.saturating_add(1);
                    if let Err(e) = save_chats_list(&self.chats) {
                        print_error(&format!("Failed to save chats: {e}"));
                    }
                }

                let text = message.text.as_deref().unwrap_or("<file>");
                println!("\n{}[event]{} new message: {}", YELLOW, RESET, text);
            }
            ServerEvent::MarkReadResult {
                with_user_id,
                updated,
            } => {
                println!(
                    "\n{}[event]{} mark_read for {} updated {} messages",
                    CYAN, RESET, with_user_id, updated
                );
                if let Some(chat) = self.chats.iter_mut().find(|c| c.user_id == with_user_id) {
                    chat.unread = 0;
                    if let Err(e) = save_chats_list(&self.chats) {
                        print_error(&format!("Failed to save chats: {e}"));
                    }
                }
            }
            ServerEvent::ReadReceipt { by_user_id, updated } => {
                println!(
                    "\n{}[event]{} read_receipt by {} for {} messages",
                    CYAN, RESET, by_user_id, updated
                );
            }
            ServerEvent::Connections { connections } => {
                println!(
                    "\n{}[event]{} {} online connection(s)",
                    CYAN,
                    RESET,
                    connections.len()
                );
            }
            ServerEvent::Pong => {
                println!("\n{}[event]{} pong", CYAN, RESET);
            }
            ServerEvent::Error { message } => {
                print_error(&format!("server error: {message}"));
            }
            ServerEvent::Joined { .. } => {}
            ServerEvent::History { .. } => {}
        }
    }

    fn ensure_chat_exists(&mut self, user_id: &str, label: Option<String>) {
        if self.chats.iter().any(|c| c.user_id == user_id) {
            return;
        }

        self.chats.push(ChatEntry {
            user_id: user_id.to_string(),
            label: label.unwrap_or_else(|| format!("user-{}", short_id(user_id))),
            unread: 0,
        });
        if let Err(e) = save_chats_list(&self.chats) {
            print_error(&format!("Failed to save chats: {e}"));
        }
    }

    async fn switch_account_menu(&mut self) {
        title("Switch Account");

        let saved_sessions = load_sessions_list();
        
        if saved_sessions.is_empty() {
            print_error("No saved sessions found");
            return;
        }

        println!("{}Saved accounts:{}", BOLD, RESET);
        for (idx, username) in saved_sessions.iter().enumerate() {
            println!("{}{}){} {}", BLUE, idx + 1, RESET, username);
        }
        println!("{}0{} Back", BLUE, RESET);

        let choice = prompt("Select account");
        
        if choice == "0" {
            return;
        }

        if let Ok(idx) = choice.parse::<usize>() {
            if idx > 0 && idx <= saved_sessions.len() {
                let selected_username = &saved_sessions[idx - 1];
                
                match load_session(selected_username) {
                    Some(token) => {
                        // Try to validate session
                        match self.auth.session_user_info(&token).await {
                            Ok(me) => {
                                self.session_token = Some(token.clone());
                                self.me = Some(me.clone());
                                self.current_username = Some(selected_username.clone());
                                
                                let _ = self.auth.set_online(&token).await;
                                print_ok(&format!("Switched to account: {} ({})", me.username, me.uuid.as_deref().unwrap_or("n/a")));
                                
                                // Reconnect WebSocket
                                if let Err(e) = self.connect_chat().await {
                                    print_error(&format!("Chat connection failed: {e}"));
                                }
                            }
                            Err(e) => {
                                print_error(&format!("Failed to validate saved session: {e}"));
                            }
                        }
                    }
                    None => {
                        print_error(&format!("Session not found for user: {}", selected_username));
                    }
                }
            } else {
                print_error("Invalid selection");
            }
        } else {
            print_error("Invalid input");
        }
    }
}

async fn connect_ws(url: &str, session_token: &str) -> Result<WsSession, String> {
    let (stream, _) = connect_async(url)
        .await
        .map_err(|e| format!("ws connect failed: {e}"))?;

    let (mut writer, mut reader) = stream.split();
    let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded_channel::<ClientAction>();
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<ServerEvent>();

    tokio::spawn(async move {
        while let Some(action) = outgoing_rx.recv().await {
            let payload = match serde_json::to_string(&action) {
                Ok(value) => value,
                Err(_) => continue,
            };

            if writer.send(Message::Text(payload.into())).await.is_err() {
                break;
            }
        }
    });

    tokio::spawn(async move {
        while let Some(message) = reader.next().await {
            let Ok(message) = message else {
                break;
            };

            match message {
                Message::Text(text) => {
                    if let Ok(event) = serde_json::from_str::<ServerEvent>(text.as_ref()) {
                        let _ = inbound_tx.send(event);
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    });

    outgoing_tx
        .send(ClientAction::Join {
            session_token: session_token.to_string(),
        })
        .map_err(|_| "failed to send join action".to_string())?;

    Ok(WsSession {
        outgoing_tx,
        inbound_rx,
    })
}

fn ensure_status_ok(status: StatusCode, body: &str) -> Result<(), String> {
    if status.is_success() {
        Ok(())
    } else {
        if let Ok(error_payload) = serde_json::from_str::<ErrorResponse>(body)
            && !error_payload.error.trim().is_empty()
        {
            return Err(format!("http {}: {}", status.as_u16(), error_payload.error));
        }

        let fallback = if body.trim().is_empty() { "<empty-body>" } else { body };
        Err(format!("http {}: {}", status.as_u16(), fallback))
    }
}

async fn ensure_ok_plain(response: reqwest::Response) -> Result<(), String> {
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| format!("read response failed: {e}"))?;

    ensure_status_ok(status, &body)?;

    if !body.trim().eq_ignore_ascii_case("ok") {
        return Err(format!("unexpected response body: {body}"));
    }

    Ok(())
}

async fn parse_plain_success(response: reqwest::Response) -> Result<String, String> {
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| format!("read response failed: {e}"))?;
    ensure_status_ok(status, &body)?;
    Ok(body)
}

async fn parse_json_success<T: for<'de> Deserialize<'de>>(response: reqwest::Response) -> Result<T, String> {
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| format!("read response failed: {e}"))?;
    ensure_status_ok(status, &body)?;
    serde_json::from_str::<T>(&body).map_err(|e| format!("json parse failed: {e}; body={body}"))
}

fn short_id(value: &str) -> String {
    value.chars().take(8).collect::<String>()
}

fn banner() {
    println!("{}{}", BLUE, BOLD);
    println!("  __  __                                      ");
    println!(" |  \\/  | ___  ___ ___  ___ _ __   __ _  ___ ");
    println!(" | |\\/| |/ _ \\/ __/ __|/ _ \\ '_ \\ / _` |/ _ \\");
    println!(" | |  | |  __/\\__ \\__ \\  __/ | | | (_| |  __/");
    println!(" |_|  |_|\\___||___/___/\\___|_| |_|\\__, |\\___|");
    println!("                                     |___/      ");
    println!("{}{}", RESET, DIM);
    println!("  interactive console client for auth + chat");
    println!("{}", RESET);
}

fn print_chat_list(chats: &[ChatEntry]) {
    println!("\n{}Saved chats:{}", BOLD, RESET);
    if chats.is_empty() {
        println!("  {}(empty){}", DIM, RESET);
        return;
    }

    for (idx, chat) in chats.iter().enumerate() {
        let mut badges = Vec::new();
        if chat.unread > 0 {
            badges.push(format!("unread={}", chat.unread));
        }

        let badges = if badges.is_empty() {
            String::new()
        } else {
            format!(" [{}]", badges.join(", "))
        };

        println!("  {:>2}. {} ({}){}", idx + 1, chat.label, chat.user_id, badges);
    }
}

fn print_profile(profile: &UserProfile) {
    println!("\n{}Profile:{}", BOLD, RESET);
    println!("  uuid           : {}", profile.uuid.as_deref().unwrap_or("n/a"));
    println!("  username       : {}", profile.username);
    println!("  first_name     : {}", profile.first_name);
    println!("  last_name      : {}", profile.last_name);
    println!("  date_of_birth  : {}", profile.date_of_birth);
    println!("  additional_info: {}", profile.additional_info);
}

fn title(text: &str) {
    println!("\n{}{}== {} =={}", BLUE, BOLD, text, RESET);
}

fn print_ok(text: &str) {
    println!("{}[ok]{} {}", GREEN, RESET, text);
}

fn print_error(text: &str) {
    eprintln!("{}[error]{} {}", RED, RESET, text);
}

fn prompt(label: &str) -> String {
    print!("{}{}{}: ", CYAN, label, RESET);
    io::stdout().flush().expect("stdout flush failed");

    let mut buf = String::new();
    if io::stdin().read_line(&mut buf).is_err() {
        return String::new();
    }

    buf.trim().to_string()
}

fn prompt_required(label: &str) -> String {
    loop {
        let value = prompt(label);
        if !value.is_empty() {
            return value;
        }
        print_error("Value cannot be empty");
    }
}

fn wait_enter() {
    println!("\n{}Press ENTER to continue...{}", DIM, RESET);
    let mut buf = String::new();
    let _ = io::stdin().read_line(&mut buf);
}

fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H");
    let _ = io::stdout().flush();
}

fn config_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config.toml")
}

fn load_config() -> Result<Config, String> {
    let path = config_path();
    let raw = fs::read_to_string(&path)
        .map_err(|e| format!("failed to read config {}: {e}", path.display()))?;

    toml::from_str::<Config>(&raw)
        .map_err(|e| format!("failed to parse config {}: {e}", path.display()))
}

#[tokio::main]
async fn main() {
    let config = match load_config() {
        Ok(c) => c,
        Err(e) => {
            print_error(&e);
            return;
        }
    };

    let mut app = App::new(config);
    app.run().await;
}
