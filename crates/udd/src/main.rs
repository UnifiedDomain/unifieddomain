use std::{io::BufReader, net::SocketAddr, sync::Arc};

use anyhow::{anyhow, Context, Result};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::{
    extract::connect_info::Connected,
    extract::{ConnectInfo, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as HyperBuilder,
    service::TowerToHyperService,
};
use rcgen::{
    BasicConstraints, Certificate as RcgenCertificate, CertificateParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rand_core::OsRng;
use rustls::{
    crypto::aws_lc_rs::default_provider,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
    version, RootCertStore, ServerConfig as RustlsServerConfig,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, types::Json as SqlJson, FromRow, PgPool, Row};
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};
use ud_common::{config::UnifiedDomainConfig, logging};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    config: Arc<UnifiedDomainConfig>,
    device_ca: Option<Arc<DeviceCa>>,
    kerberos: Option<KerberosSync>,
}

#[derive(Clone)]
struct DeviceCa {
    cert: Arc<RcgenCertificate>,
    cert_pem: String,
}

#[derive(Clone)]
struct KerberosSync {
    realm: String,
    kadmin_path: std::path::PathBuf,
    keytab_dir: std::path::PathBuf,
}

#[derive(Clone, Debug)]
struct TlsConnectInfo {
    remote_addr: SocketAddr,
    peer_certificates: Vec<CertificateDer<'static>>,
}

impl Connected<TlsConnectInfo> for TlsConnectInfo {
    fn connect_info(target: TlsConnectInfo) -> Self {
        target
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_json_logging_stdout().context("init logging")?;
    let cfg = Arc::new(UnifiedDomainConfig::load().context("load config")?);

    info!(listen = %cfg.server.listen_addr, "starting udd");

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&cfg.database.url)
        .await
        .context("connect database")?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("run migrations")?;

    let (tls_config, device_ca) = build_tls_config(&cfg).context("build tls config")?;
    let kerberos = setup_kerberos(&cfg)?;

    let state = AppState {
        pool,
        config: cfg.clone(),
        device_ca,
        kerberos,
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/bootstrap", post(bootstrap))
        .route("/v1/login", post(login))
        .route("/v1/users", post(create_user))
        .route("/v1/users/:id", get(get_user))
        .route("/v1/groups", post(create_group))
        .route("/v1/groups/:id/members", post(add_group_member))
        .route("/v1/devices/enroll", post(enroll_device))
        .route("/v1/devices/:id/trust", post(update_device_trust))
        .route("/v1/kerberos/users/:id/commands", post(kerberos_user_commands))
        .route(
            "/v1/kerberos/devices/:id/commands",
            post(kerberos_device_commands),
        )
        .route("/v1/policies", post(create_policy))
        .route("/v1/ssh/authorized_keys", get(authorized_keys))
        .route("/v1/audit", get(list_audit))
        .with_state(state.clone());

    let addr: SocketAddr = cfg
        .server
        .listen_addr
        .parse()
        .context("invalid listen_addr")?;

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind listen socket {addr}"))?;
    let tls_acceptor = TlsAcceptor::from(tls_config.get_inner());

    loop {
        let (stream, remote_addr) = listener
            .accept()
            .await
            .context("accept tcp connection")?;

        let acceptor = tls_acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let builder = HyperBuilder::new(TokioExecutor::new());
            let tls_stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(err) => {
                    warn!(error = %err, "tls accept failed");
                    return;
                }
            };

            let peer_certificates = tls_stream
                .get_ref()
                .1
                .peer_certificates()
                .map(|certs| certs.to_vec())
                .unwrap_or_default();
            let info = TlsConnectInfo {
                remote_addr,
                peer_certificates,
            };

            let service = app.layer(middleware::from_fn(
                move |mut req: axum::http::Request<axum::body::Body>, next: middleware::Next| {
                    let info = info.clone();
                    async move {
                        req.extensions_mut().insert(info.clone());
                        next.run(req).await
                    }
                },
            ));

            let service = TowerToHyperService::new(service);

            let io = TokioIo::new(tls_stream);
            if let Err(err) = builder.serve_connection_with_upgrades(io, service).await {
                warn!(error = %err, "connection error");
            }
        });
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

#[derive(Debug, Serialize)]
struct ApiErrorBody {
    error: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, msg: impl Into<String>) -> Self {
        Self {
            status,
            message: msg.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(ApiErrorBody { error: self.message });
        (self.status, body).into_response()
    }
}

#[derive(Debug, Deserialize)]
struct BootstrapRequest {
    admin_username: String,
    admin_password: String,
    display_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct BootstrapResponse {
    admin_token: String,
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    result: String,
}

async fn bootstrap(
    State(state): State<AppState>,
    Json(req): Json<BootstrapRequest>,
) -> Result<Json<BootstrapResponse>, ApiError> {
    let request_id = Uuid::new_v4();
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&state.pool)
        .await
        .map_err(db_err)?;

    if count.0 > 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "already initialized; bootstrap is one-time",
        ));
    }

    let admin_group_id = ensure_group(&state, "ops-admins").await?;

    let password_hash = hash_password(&req.admin_password)
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let user_id = Uuid::new_v4();
    let display = req
        .display_name
        .unwrap_or_else(|| req.admin_username.clone());

    sqlx::query("INSERT INTO users (id, username, display_name, password_hash, status) VALUES ($1, $2, $3, $4, 'active')")
        .bind(user_id)
        .bind(&req.admin_username)
        .bind(&display)
        .bind(password_hash)
        .execute(&state.pool)
        .await
        .map_err(db_err)?;

    if let Some(k) = state.kerberos.as_ref() {
        sync_kerberos_user(k, &req.admin_username).map_err(|e| {
            warn!(error = %e, "kerberos user sync failed");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "kerberos sync failed; check kadmin configuration",
            )
        })?;
    }

    sqlx::query("INSERT INTO group_memberships (user_id, group_id) VALUES ($1, $2)")
        .bind(user_id)
        .bind(admin_group_id)
        .execute(&state.pool)
        .await
        .map_err(db_err)?;

    audit_log(
        &state,
        request_id,
        Some(&req.admin_username),
        None,
        "bootstrap",
        "system",
        "allow",
        "bootstrap completed",
        None,
    )
    .await;

    Ok(Json(BootstrapResponse {
        admin_token: state.config.auth.admin_token.clone(),
    }))
}

async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let request_id = Uuid::new_v4();
    let row = sqlx::query_as::<_, LoginRow>(
        "SELECT username, password_hash, status FROM users WHERE username = $1",
    )
    .bind(&req.username)
    .fetch_optional(&state.pool)
    .await
    .map_err(db_err)?;

    let Some(row) = row else {
        audit_log(
            &state,
            request_id,
            Some(&req.username),
            None,
            "login",
            "user",
            "deny",
            "user not found",
            None,
        )
        .await;
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "invalid credentials"));
    };

    if row.status != "active" {
        audit_log(
            &state,
            request_id,
            Some(&req.username),
            None,
            "login",
            "user",
            "deny",
            "user disabled",
            None,
        )
        .await;
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "invalid credentials"));
    }

    let ok = verify_password(&req.password, &row.password_hash)
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if !ok {
        audit_log(
            &state,
            request_id,
            Some(&req.username),
            None,
            "login",
            "user",
            "deny",
            "bad password",
            None,
        )
        .await;
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "invalid credentials"));
    }

    audit_log(
        &state,
        request_id,
        Some(&req.username),
        None,
        "login",
        "user",
        "allow",
        "password verified",
        None,
    )
    .await;

    Ok(Json(LoginResponse {
        result: "ok".into(),
    }))
}

#[derive(Debug, Deserialize)]
struct CreateUserRequest {
    username: String,
    display_name: String,
    password: String,
    ssh_public_keys: Option<Vec<String>>,
}

#[derive(Debug, Serialize, FromRow)]
struct UserResponse {
    id: Uuid,
    username: String,
    display_name: String,
    status: String,
    ssh_public_keys: Vec<String>,
    created_at: OffsetDateTime,
}

async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    tls: Option<ConnectInfo<TlsConnectInfo>>,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    let tls_ref = tls.as_ref().map(|ci| &ci.0);
    enforce_admin(&state, &headers, tls_ref)?;
    let request_id = Uuid::new_v4();
    let hash = hash_password(&req.password)
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let user_id = Uuid::new_v4();
    let keys = req.ssh_public_keys.unwrap_or_default();

    let rec = sqlx::query_as::<_, UserResponse>(
        r#"
        INSERT INTO users (id, username, display_name, password_hash, status, ssh_public_keys)
        VALUES ($1, $2, $3, $4, 'active', $5)
        RETURNING id, username, display_name, status, ssh_public_keys, created_at
        "#,
    )
    .bind(user_id)
    .bind(&req.username)
    .bind(&req.display_name)
    .bind(hash)
    .bind(&keys)
    .fetch_one(&state.pool)
    .await
    .map_err(db_err)?;

    audit_log(
        &state,
        request_id,
        Some(&rec.username),
        None,
        "create_user",
        "user",
        "allow",
        "user created",
        None,
    )
    .await;

    if let Some(k) = state.kerberos.as_ref() {
        sync_kerberos_user(k, &req.username).map_err(|e| {
            warn!(error = %e, "kerberos user sync failed");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "kerberos sync failed; check kadmin configuration",
            )
        })?;
    }
    Ok(Json(rec))
}

async fn get_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    tls: Option<ConnectInfo<TlsConnectInfo>>,
    Path(id): Path<Uuid>,
) -> Result<Json<UserResponse>, ApiError> {
    let tls_ref = tls.as_ref().map(|ci| &ci.0);
    enforce_admin(&state, &headers, tls_ref)?;
    let rec = sqlx::query_as::<_, UserResponse>(
        "SELECT id, username, display_name, status, ssh_public_keys, created_at FROM users WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "user not found"))?;

    Ok(Json(rec))
}

#[derive(Debug, Deserialize)]
struct CreateGroupRequest {
    name: String,
}

#[derive(Debug, Serialize, FromRow)]
struct GroupResponse {
    id: Uuid,
    name: String,
    created_at: OffsetDateTime,
}

async fn create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    tls: Option<ConnectInfo<TlsConnectInfo>>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<Json<GroupResponse>, ApiError> {
    let tls_ref = tls.as_ref().map(|ci| &ci.0);
    enforce_admin(&state, &headers, tls_ref)?;
    let group_id = Uuid::new_v4();
    let rec = sqlx::query_as::<_, GroupResponse>(
        r#"
        INSERT INTO groups (id, name) VALUES ($1, $2)
        RETURNING id, name, created_at
        "#,
    )
    .bind(group_id)
    .bind(&req.name)
    .fetch_one(&state.pool)
    .await
    .map_err(db_err)?;

    Ok(Json(rec))
}

#[derive(Debug, Deserialize)]
struct AddGroupMemberRequest {
    user_id: Uuid,
}

async fn add_group_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    tls: Option<ConnectInfo<TlsConnectInfo>>,
    Path(group_id): Path<Uuid>,
    Json(req): Json<AddGroupMemberRequest>,
) -> Result<StatusCode, ApiError> {
    let tls_ref = tls.as_ref().map(|ci| &ci.0);
    enforce_admin(&state, &headers, tls_ref)?;
    sqlx::query("INSERT INTO group_memberships (user_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
        .bind(req.user_id)
        .bind(group_id)
        .execute(&state.pool)
        .await
        .map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct EnrollDeviceRequest {
    name: String,
    device_type: String,
    tags: Vec<String>,
    host_fingerprint: Option<String>,
    pubkey_fingerprint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateDeviceTrustRequest {
    trust_state: String,
}

#[derive(Debug, Serialize)]
struct EnrollDeviceResponse {
    device_id: Uuid,
    trust_state: String,
    device_cert_pem: String,
    device_key_pem: String,
    ca_cert_pem: Option<String>,
}

async fn enroll_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    tls: Option<ConnectInfo<TlsConnectInfo>>,
    Json(req): Json<EnrollDeviceRequest>,
) -> Result<Json<EnrollDeviceResponse>, ApiError> {
    let tls_ref = tls.as_ref().map(|ci| &ci.0);
    enforce_admin(&state, &headers, tls_ref)?;
    let device_ca = state.device_ca.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::FAILED_DEPENDENCY,
            "mTLS CA not configured; cannot issue device cert",
        )
    })?;
    let device_id = Uuid::new_v4();
    let trust_state = "enrolled".to_string();
    let device_cert = generate_device_cert(device_id, &req.name, &device_ca)
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    sqlx::query(
        r#"
        INSERT INTO devices (id, name, device_type, tags, trust_state, host_fingerprint, pubkey_fingerprint, device_cert_pem, device_cert_fingerprint)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(device_id)
    .bind(&req.name)
    .bind(&req.device_type)
    .bind(&req.tags)
    .bind(&trust_state)
    .bind(&req.host_fingerprint)
    .bind(&req.pubkey_fingerprint)
    .bind(&device_cert.cert_pem)
    .bind(&device_cert.fingerprint)
    .execute(&state.pool)
    .await
    .map_err(db_err)?;

    Ok(Json(EnrollDeviceResponse {
        device_id,
        trust_state,
        device_cert_pem: device_cert.cert_pem,
        device_key_pem: device_cert.key_pem,
        ca_cert_pem: Some(device_ca.cert_pem.clone()),
    }))
}

async fn update_device_trust(
    State(state): State<AppState>,
    headers: HeaderMap,
    tls: Option<ConnectInfo<TlsConnectInfo>>,
    Path(device_id): Path<Uuid>,
    Json(req): Json<UpdateDeviceTrustRequest>,
) -> Result<StatusCode, ApiError> {
    let tls_ref = tls.as_ref().map(|ci| &ci.0);
    enforce_admin(&state, &headers, tls_ref)?;

    let trust = req.trust_state.to_lowercase();
    if trust != "trusted" && trust != "revoked" && trust != "enrolled" {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "trust_state must be one of enrolled|trusted|revoked",
        ));
    }

    let rows = sqlx::query("UPDATE devices SET trust_state = $1 WHERE id = $2")
        .bind(&trust)
        .bind(device_id)
        .execute(&state.pool)
        .await
        .map_err(db_err)?;

    if rows.rows_affected() == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "device not found"));
    }

    audit_log(
        &state,
        Uuid::new_v4(),
        None,
        Some(device_id),
        "device_trust_update",
        "admin",
        "allow",
        &trust,
        None,
    )
    .await;

    if trust == "trusted" {
        if let Some(k) = state.kerberos.as_ref() {
            let device = sqlx::query_as::<_, DeviceRow>(
                "SELECT id, name, tags, trust_state, host_fingerprint, device_cert_fingerprint FROM devices WHERE id = $1",
            )
            .bind(device_id)
            .fetch_one(&state.pool)
            .await
            .map_err(db_err)?;

            sync_kerberos_host(k, &device).map_err(|e| {
                warn!(error = %e, "kerberos host sync failed");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "kerberos sync failed; check kadmin configuration",
                )
            })?;
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn kerberos_user_commands(
    State(state): State<AppState>,
    headers: HeaderMap,
    tls: Option<ConnectInfo<TlsConnectInfo>>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<KerberosCommandResponse>, ApiError> {
    let tls_ref = tls.as_ref().map(|ci| &ci.0);
    enforce_admin(&state, &headers, tls_ref)?;

    let user = sqlx::query_as::<_, UserAuthRow>(
        "SELECT id, username, status, ssh_public_keys FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "user not found"))?;

    if user.status != "active" {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "user not active; activate before provisioning",
        ));
    }

    let realm = realm(&state.config);
    let principal = format!("{}@{}", user.username, realm);
    let cmds = vec![
        format!("kadmin.local -q \"addprinc -randkey {}\"", principal),
        format!(
            "kadmin.local -q \"ktadd -k /etc/krb5.keytab {}\"",
            principal
        ),
    ];

    Ok(Json(KerberosCommandResponse { commands: cmds }))
}

async fn kerberos_device_commands(
    State(state): State<AppState>,
    headers: HeaderMap,
    tls: Option<ConnectInfo<TlsConnectInfo>>,
    Path(device_id): Path<Uuid>,
) -> Result<Json<KerberosCommandResponse>, ApiError> {
    let tls_ref = tls.as_ref().map(|ci| &ci.0);
    enforce_admin(&state, &headers, tls_ref)?;

    let device = sqlx::query_as::<_, DeviceRow>(
        "SELECT id, name, tags, trust_state, host_fingerprint, device_cert_fingerprint FROM devices WHERE id = $1",
    )
    .bind(device_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "device not found"))?;

    let realm = realm(&state.config);
    let host = device
        .name
        .unwrap_or_else(|| format!("device-{}", device.id));
    let principal = format!("host/{}@{}", host, realm);
    let cmds = vec![
        format!("kadmin.local -q \"addprinc -randkey {}\"", principal),
        format!(
            "kadmin.local -q \"ktadd -k /etc/krb5.keytab {}\"",
            principal
        ),
    ];

    Ok(Json(KerberosCommandResponse { commands: cmds }))
}

#[derive(Debug, Deserialize)]
struct CreatePolicyRequest {
    group_id: Uuid,
    host_tag: String,
    effect: String,
    description: Option<String>,
}

#[derive(Debug, Serialize, FromRow)]
struct PolicyResponse {
    id: Uuid,
    group_id: Uuid,
    host_tag: String,
    effect: String,
    description: Option<String>,
}

#[derive(Debug, Serialize)]
struct KerberosCommandResponse {
    commands: Vec<String>,
}

#[derive(Debug, FromRow)]
struct UserAuthRow {
    id: Uuid,
    username: String,
    status: String,
    ssh_public_keys: Vec<String>,
}

#[derive(Debug, FromRow)]
struct DeviceRow {
    id: Uuid,
    tags: Vec<String>,
    trust_state: String,
    host_fingerprint: Option<String>,
    device_cert_fingerprint: Option<String>,
    name: Option<String>,
}

#[derive(Debug, FromRow)]
struct GroupIdRow {
    group_id: Uuid,
}

#[derive(Debug, FromRow)]
struct PolicyRow {
    group_id: Uuid,
    host_tag: String,
    effect: String,
}

#[derive(Debug, FromRow)]
struct LoginRow {
    username: String,
    password_hash: String,
    status: String,
}

async fn create_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    tls: Option<ConnectInfo<TlsConnectInfo>>,
    Json(req): Json<CreatePolicyRequest>,
) -> Result<Json<PolicyResponse>, ApiError> {
    let tls_ref = tls.as_ref().map(|ci| &ci.0);
    enforce_admin(&state, &headers, tls_ref)?;
    if req.effect != "allow" && req.effect != "deny" {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "effect must be allow or deny"));
    }
    let policy_id = Uuid::new_v4();
    let rec = sqlx::query_as::<_, PolicyResponse>(
        r#"
        INSERT INTO ssh_policies (id, group_id, host_tag, effect, description)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, group_id, host_tag, effect, description
        "#,
    )
    .bind(policy_id)
    .bind(req.group_id)
    .bind(&req.host_tag)
    .bind(&req.effect)
    .bind(&req.description)
    .fetch_one(&state.pool)
    .await
    .map_err(db_err)?;

    Ok(Json(rec))
}

#[derive(Debug, Deserialize)]
struct AuthorizedKeysQuery {
    username: String,
    host_fingerprint: Option<String>,
}

async fn authorized_keys(
    State(state): State<AppState>,
    ConnectInfo(tls): ConnectInfo<TlsConnectInfo>,
    Query(q): Query<AuthorizedKeysQuery>,
) -> Result<Response, ApiError> {
    let request_id = Uuid::new_v4();

    let client_fp = match client_cert_fingerprint(&tls) {
        Some(fp) => fp,
        None => {
            audit_log(
                &state,
                request_id,
                Some(&q.username),
                None,
                "ssh_authorize",
                "ssh",
                "deny",
                "client certificate required",
                None,
            )
            .await;
            return Ok((StatusCode::UNAUTHORIZED, "").into_response());
        }
    };

    let user = sqlx::query_as::<_, UserAuthRow>(
        "SELECT id, username, status, ssh_public_keys FROM users WHERE username = $1",
    )
    .bind(&q.username)
    .fetch_optional(&state.pool)
    .await
    .map_err(db_err)?;

    let user = match user {
        Some(u) if u.status == "active" => u,
        _ => {
            audit_log(
                &state,
                request_id,
                Some(&q.username),
                None,
                "ssh_authorize",
                "ssh",
                "deny",
                "user not active",
                None,
            )
            .await;
            return Ok((StatusCode::OK, "").into_response());
        }
    };

    let device = sqlx::query_as::<_, DeviceRow>(
        "SELECT id, tags, trust_state, host_fingerprint, device_cert_fingerprint FROM devices WHERE device_cert_fingerprint = $1",
    )
    .bind(&client_fp)
    .fetch_optional(&state.pool)
    .await
    .map_err(db_err)?;

    let device = match device {
        Some(d) if d.trust_state == "trusted" => d,
        _ => {
            audit_log(
                &state,
                request_id,
                Some(&q.username),
                None,
                "ssh_authorize",
                "ssh",
                "deny",
                "device not trusted",
                None,
            )
            .await;
            return Ok((StatusCode::OK, "").into_response());
        }
    };

    match (q.host_fingerprint.as_deref(), device.host_fingerprint.as_deref()) {
        (Some(requested), Some(stored)) if requested != stored => {
            audit_log(
                &state,
                request_id,
                Some(&q.username),
                Some(device.id),
                "ssh_authorize",
                "ssh",
                "deny",
                "host fingerprint mismatch",
                None,
            )
            .await;
            return Ok((StatusCode::OK, "").into_response());
        }
        (Some(_), None) => {
            audit_log(
                &state,
                request_id,
                Some(&q.username),
                Some(device.id),
                "ssh_authorize",
                "ssh",
                "deny",
                "device missing host fingerprint binding",
                None,
            )
            .await;
            return Ok((StatusCode::OK, "").into_response());
        }
        (None, Some(_)) => {
            audit_log(
                &state,
                request_id,
                Some(&q.username),
                Some(device.id),
                "ssh_authorize",
                "ssh",
                "deny",
                "host fingerprint required",
                None,
            )
            .await;
            return Ok((StatusCode::OK, "").into_response());
        }
        _ => {}
    }

    let groups = sqlx::query_as::<_, GroupIdRow>(
        "SELECT group_id FROM group_memberships WHERE user_id = $1",
    )
    .bind(user.id)
    .fetch_all(&state.pool)
    .await
    .map_err(db_err)?;

    let group_ids: Vec<Uuid> = groups.into_iter().map(|g| g.group_id).collect();
    if group_ids.is_empty() {
        audit_log(
            &state,
            request_id,
            Some(&q.username),
            Some(device.id),
            "ssh_authorize",
            "ssh",
            "deny",
            "no group membership",
            None,
        )
        .await;
        return Ok((StatusCode::OK, "").into_response());
    }

    let tags = device.tags;
    let policies = sqlx::query_as::<_, PolicyRow>(
        "SELECT group_id, host_tag, effect FROM ssh_policies WHERE group_id = ANY($1) AND host_tag = ANY($2)",
    )
    .bind(&group_ids)
    .bind(&tags)
    .fetch_all(&state.pool)
    .await
    .map_err(db_err)?;

    let decision = evaluate_policies(&policies);

    audit_log(
        &state,
        request_id,
        Some(&q.username),
        Some(device.id),
        "ssh_authorize",
        "ssh",
        decision,
        if decision == "allow" { "policy allow" } else { "no matching allow" },
        None,
    )
    .await;

    if decision == "allow" {
        let keys = user.ssh_public_keys;
        let body = keys.join("\n");
        Ok((StatusCode::OK, body).into_response())
    } else {
        Ok((StatusCode::OK, String::new()).into_response())
    }
}

#[derive(Debug, Deserialize)]
struct AuditQuery {
    limit: Option<i64>,
}

#[derive(Debug, Serialize, FromRow)]
struct AuditRecord {
    id: i64,
    created_at: OffsetDateTime,
    request_id: Option<Uuid>,
    actor_username: Option<String>,
    device_id: Option<Uuid>,
    action: String,
    target: Option<String>,
    result: String,
    reason: Option<String>,
    details: Option<serde_json::Value>,
}

async fn list_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    tls: Option<ConnectInfo<TlsConnectInfo>>,
    Query(q): Query<AuditQuery>,
) -> Result<Json<Vec<AuditRecord>>, ApiError> {
    let tls_ref = tls.as_ref().map(|ci| &ci.0);
    enforce_admin(&state, &headers, tls_ref)?;
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let rows = sqlx::query_as::<_, AuditRecord>(
        r#"
        SELECT id, created_at, request_id, actor_username, device_id, action, target, result, reason, details
        FROM audit_logs
        ORDER BY id DESC
        LIMIT $1
        "#,
    )
    .bind(limit)
    .fetch_all(&state.pool)
    .await
    .map_err(db_err)?;

    Ok(Json(rows))
}

fn enforce_admin(
    state: &AppState,
    headers: &HeaderMap,
    tls: Option<&TlsConnectInfo>,
) -> Result<(), ApiError> {
    if let Some(tls) = tls {
        if client_cert_fingerprint(tls).is_some() {
            return Ok(());
        }
    }

    if !state.config.auth.admin_token_enabled {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "admin token disabled; use mTLS"));
    }

    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "missing Authorization header"));
    };
    let Ok(value_str) = value.to_str() else {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "invalid Authorization header"));
    };
    let prefix = "Bearer ";
    if let Some(token) = value_str.strip_prefix(prefix) {
        if token == state.config.auth.admin_token {
            return Ok(());
        }
    }
    Err(ApiError::new(StatusCode::UNAUTHORIZED, "invalid admin token"))
}

fn db_err(err: sqlx::Error) -> ApiError {
    warn!(error = %err, "database error");
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "database error")
}

fn hash_password(plain: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon = Argon2::default();
    let hash = argon
        .hash_password(plain.as_bytes(), &salt)
        .map_err(|e| anyhow!(e))?;
    Ok(hash.to_string())
}

fn verify_password(plain: &str, stored: &str) -> Result<bool> {
    let parsed = PasswordHash::new(stored).map_err(|e| anyhow!(e))?;
    let argon = Argon2::default();
    Ok(argon.verify_password(plain.as_bytes(), &parsed).is_ok())
}

fn evaluate_policies(policies: &[PolicyRow]) -> &'static str {
    let mut decision = "deny";
    for p in policies {
        if p.effect == "deny" {
            return "deny";
        }
        if p.effect == "allow" {
            decision = "allow";
        }
    }
    decision
}

struct GeneratedDeviceCert {
    cert_pem: String,
    key_pem: String,
    fingerprint: String,
}

fn generate_device_cert(device_id: Uuid, name: &str, device_ca: &Arc<DeviceCa>) -> Result<GeneratedDeviceCert> {
    let mut params = CertificateParams::new(vec![name.to_string()]);
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, format!("device-{device_id}"));
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
        KeyUsagePurpose::KeyAgreement,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.subject_alt_names = vec![SanType::DnsName(name.to_string())];

    let cert = RcgenCertificate::from_params(params)?;
    let cert_pem = cert.serialize_pem_with_signer(&device_ca.cert)?;
    let key_pem = cert.serialize_private_key_pem();
    let fingerprint = fingerprint_pem(&cert_pem)?;

    Ok(GeneratedDeviceCert {
        cert_pem,
        key_pem,
        fingerprint,
    })
}

fn fingerprint_pem(pem: &str) -> Result<String> {
    let mut reader = BufReader::new(pem.as_bytes());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| anyhow!("parse pem: {e}"))?;
    let first = certs
        .first()
        .ok_or_else(|| anyhow!("no certificate found in pem"))?;
    Ok(fingerprint_cert_der(first))
}

fn fingerprint_cert_der(cert: &CertificateDer<'_>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert);
    let digest = hasher.finalize();
    hex::encode_upper(digest)
}

fn load_device_ca(cert_path: &str, key_path: &str) -> Result<DeviceCa> {
    let cert_pem = std::fs::read_to_string(cert_path).context("read mtls ca cert")?;
    let key_pem = std::fs::read_to_string(key_path).context("read mtls ca key")?;
    let key_pair = KeyPair::from_pem(&key_pem).context("parse ca key")?;
    let mut params = CertificateParams::from_ca_cert_pem(&cert_pem, key_pair)
        .context("parse ca cert for rcgen")?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let cert = RcgenCertificate::from_params(params).context("build rcgen ca")?;
    Ok(DeviceCa {
        cert: Arc::new(cert),
        cert_pem,
    })
}

fn load_device_ca_from_config(cfg: &UnifiedDomainConfig) -> Result<Option<Arc<DeviceCa>>> {
    match (&cfg.auth.mtls_ca_cert_path, &cfg.auth.mtls_ca_key_path) {
        (Some(cert), Some(key)) => Ok(Some(Arc::new(load_device_ca(cert, key)?))),
        _ => Ok(None),
    }
}

fn build_tls_config(cfg: &UnifiedDomainConfig) -> Result<(RustlsConfig, Option<Arc<DeviceCa>>)> {
    let server_certs = load_cert_chain(std::path::Path::new(&cfg.server.tls_cert_path))?;
    let server_key = load_private_key(std::path::Path::new(&cfg.server.tls_key_path))?;

    let provider = default_provider();
    let builder = RustlsServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&version::TLS13, &version::TLS12])?;

    // Treat empty strings as unset so mTLS can be disabled via env/config overrides.
    let ca_cert_path = cfg
        .auth
        .mtls_ca_cert_path
        .as_deref()
        .filter(|s| !s.is_empty());
    let ca_key_path = cfg
        .auth
        .mtls_ca_key_path
        .as_deref()
        .filter(|s| !s.is_empty());

    let (client_auth, device_ca) = match (ca_cert_path, ca_key_path) {
        (Some(ca_cert_path), Some(ca_key_path)) => {
            let ca = Arc::new(load_device_ca(ca_cert_path, ca_key_path)?);
            let mut roots = RootCertStore::empty();
            roots.add_parsable_certificates(load_cert_chain(std::path::Path::new(ca_cert_path))?);
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .context("build mtls client verifier")?;
            (Some(verifier), Some(ca))
        }
        _ => (None, None),
    };

    let tls = if let Some(verifier) = client_auth {
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_certs, server_key)?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(server_certs, server_key)?
    };

    Ok((RustlsConfig::from_config(Arc::new(tls)), device_ca))
}

fn load_cert_chain(path: &std::path::Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(std::fs::File::open(path).context("open cert chain")?);
    rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| anyhow!("read cert chain: {e}"))
}

fn load_private_key(path: &std::path::Path) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(std::fs::File::open(path).context("open private key")?);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| anyhow!("read private key: {e}"))?
        .ok_or_else(|| anyhow!("no private key found"))
}

fn realm(cfg: &UnifiedDomainConfig) -> String {
    cfg.domain
        .as_deref()
        .unwrap_or("UD.INTERNAL")
        .to_uppercase()
}

fn client_cert_fingerprint(info: &TlsConnectInfo) -> Option<String> {
    info
        .peer_certificates
        .first()
        .map(fingerprint_cert_der)
}

fn setup_kerberos(cfg: &UnifiedDomainConfig) -> Result<Option<KerberosSync>> {
    let Some(kcfg) = cfg.kerberos.as_ref() else {
        return Ok(None);
    };
    if !kcfg.enabled {
        return Ok(None);
    }

    let kadmin_path = kcfg
        .kadmin_path
        .as_ref()
        .ok_or_else(|| anyhow!("kerberos.enabled=true but kadmin_path not set"))?;
    let keytab_dir = kcfg
        .keytab_dir
        .as_ref()
        .ok_or_else(|| anyhow!("kerberos.enabled=true but keytab_dir not set"))?;
    let realm = kcfg
        .realm
        .clone()
        .or_else(|| cfg.domain.clone())
        .unwrap_or_else(|| "UD.INTERNAL".into());

    std::fs::create_dir_all(keytab_dir)
        .with_context(|| format!("create keytab dir {keytab_dir:?}"))?;

    Ok(Some(KerberosSync {
        realm: realm.to_uppercase(),
        kadmin_path: kadmin_path.clone(),
        keytab_dir: keytab_dir.clone(),
    }))
}

fn sync_kerberos_user(k: &KerberosSync, username: &str) -> Result<()> {
    let principal = format!("{}@{}", username, k.realm);
    let keytab = k.keytab_dir.join(format!("{}.keytab", username));
    ensure_principal(k, &principal)?;
    ktadd(k, &principal, &keytab)
}

fn sync_kerberos_host(k: &KerberosSync, device: &DeviceRow) -> Result<()> {
    let host = device
        .name
        .clone()
        .unwrap_or_else(|| format!("device-{}", device.id));
    let principal = format!("host/{}@{}", host, k.realm);
    let keytab = k.keytab_dir.join(format!("host-{}.keytab", device.id));
    ensure_principal(k, &principal)?;
    ktadd(k, &principal, &keytab)
}

fn ensure_principal(k: &KerberosSync, principal: &str) -> Result<()> {
    let status = std::process::Command::new(&k.kadmin_path)
        .arg("-q")
        .arg(format!("getprinc {}", principal))
        .status()
        .with_context(|| format!("run kadmin getprinc for {principal}"))?;

    if status.success() {
        return Ok(());
    }

    let status = std::process::Command::new(&k.kadmin_path)
        .arg("-q")
        .arg(format!("addprinc -randkey {}", principal))
        .status()
        .with_context(|| format!("run kadmin addprinc for {principal}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("kadmin addprinc failed for {principal}"))
    }
}

fn ktadd(k: &KerberosSync, principal: &str, keytab: &std::path::Path) -> Result<()> {
    let status = std::process::Command::new(&k.kadmin_path)
        .arg("-q")
        .arg(format!("ktadd -k {} {}", keytab.display(), principal))
        .status()
        .with_context(|| format!("run kadmin ktadd for {principal}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("kadmin ktadd failed for {principal}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::State, Json};
    use http_body_util::BodyExt as _;
    use std::io::BufReader;
    use std::env;

    #[test]
    fn policy_deny_takes_precedence() {
        let pols = vec![
            PolicyRow {
                group_id: Uuid::new_v4(),
                host_tag: "server".into(),
                effect: "allow".into(),
            },
            PolicyRow {
                group_id: Uuid::new_v4(),
                host_tag: "server".into(),
                effect: "deny".into(),
            },
        ];
        assert_eq!(evaluate_policies(&pols), "deny");
    }

    #[test]
    fn policy_allow_when_present() {
        let pols = vec![PolicyRow {
            group_id: Uuid::new_v4(),
            host_tag: "server".into(),
            effect: "allow".into(),
        }];
        assert_eq!(evaluate_policies(&pols), "allow");
    }

    #[test]
    fn policy_default_deny() {
        let pols: Vec<PolicyRow> = vec![];
        assert_eq!(evaluate_policies(&pols), "deny");
    }

    #[tokio::test]
    async fn happy_path_bootstrap_and_enroll() {
        let db_url = env::var("TEST_DATABASE_URL").or_else(|_| env::var("DATABASE_URL"));
        let db_url = match db_url {
            Ok(url) => url,
            Err(_) => {
                eprintln!("skipping integration test; DATABASE_URL not set");
                return;
            }
        };

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .unwrap();

        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        sqlx::query("TRUNCATE audit_logs, ssh_policies, group_memberships, devices, users, groups RESTART IDENTITY CASCADE")
            .execute(&pool)
            .await
            .unwrap();

        let cfg = UnifiedDomainConfig {
            server: ud_common::config::ServerConfig {
                listen_addr: "127.0.0.1:0".into(),
                tls_cert_path: "deploy/certs/udd.pem".into(),
                tls_key_path: "deploy/certs/udd-key.pem".into(),
            },
            auth: ud_common::config::AuthConfig {
                admin_token: "test-admin".into(),
                mtls_ca_cert_path: None,
                mtls_ca_key_path: None,
                admin_token_enabled: true,
            },
            database: ud_common::config::DatabaseConfig { url: db_url.clone() },
            domain: Some("UD.INTERNAL".into()),
            kerberos: None,
        };

        let device_ca = Arc::new(make_test_device_ca());
        let state = AppState {
            pool,
            config: Arc::new(cfg),
            device_ca: Some(device_ca),
            kerberos: None,
        };

        let bootstrap_resp = bootstrap(
            State(state.clone()),
            Json(BootstrapRequest {
                admin_username: "admin".into(),
                admin_password: "Password!23".into(),
                display_name: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(bootstrap_resp.0.admin_token, state.config.auth.admin_token);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", state.config.auth.admin_token).parse().unwrap(),
        );

        let user = create_user(
            State(state.clone()),
            headers.clone(),
            None,
            Json(CreateUserRequest {
                username: "alice".into(),
                display_name: "Alice".into(),
                password: "Password!23".into(),
                ssh_public_keys: Some(vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItests".into()]),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(user.username, "alice");

        let group = create_group(
            State(state.clone()),
            headers.clone(),
            None,
            Json(CreateGroupRequest { name: "ops-admins".into() }),
        )
        .await
        .unwrap()
        .0;

        add_group_member(
            State(state.clone()),
            headers.clone(),
            None,
            axum::extract::Path(group.id),
            Json(AddGroupMemberRequest { user_id: user.id }),
        )
        .await
        .unwrap();

        let policy = create_policy(
            State(state.clone()),
            headers.clone(),
            None,
            Json(CreatePolicyRequest {
                group_id: group.id,
                host_tag: "server".into(),
                effect: "allow".into(),
                description: Some("allow ops".into()),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(policy.effect, "allow");

        let device = enroll_device(
            State(state.clone()),
            headers.clone(),
            None,
            Json(EnrollDeviceRequest {
                name: "host1".into(),
                device_type: "server".into(),
                tags: vec!["server".into()],
                host_fingerprint: Some("host-fp".into()),
                pubkey_fingerprint: None,
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(device.trust_state, "enrolled");
        assert!(device.device_cert_pem.contains("BEGIN CERTIFICATE"));

        update_device_trust(
            State(state.clone()),
            headers.clone(),
            None,
            Path(device.device_id),
            Json(UpdateDeviceTrustRequest {
                trust_state: "trusted".into(),
            }),
        )
        .await
        .unwrap();

        let cert_der = {
            let mut reader = BufReader::new(device.device_cert_pem.as_bytes());
            let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
                .collect::<std::result::Result<_, _>>()
                .unwrap();
            certs.into_iter().next().unwrap()
        };

        let tls = TlsConnectInfo {
            remote_addr: "127.0.0.1:0".parse().unwrap(),
            peer_certificates: vec![cert_der],
        };

        let resp = authorized_keys(
            State(state.clone()),
            ConnectInfo(tls),
            Query(AuthorizedKeysQuery {
                username: "alice".into(),
                host_fingerprint: Some("host-fp".into()),
            }),
        )
        .await
        .unwrap();

        let (parts, body) = resp.into_parts();
        assert_eq!(parts.status, StatusCode::OK);
        let body_bytes = body.collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body_str.contains("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItests"));
    }

    fn make_test_device_ca() -> DeviceCa {
        let mut params = CertificateParams::new(vec!["ud-ca".into()]);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = RcgenCertificate::from_params(params).expect("create ca cert");
        let cert_pem = cert.serialize_pem().expect("serialize ca cert");
        DeviceCa {
            cert: Arc::new(cert),
            cert_pem,
        }
    }
}

async fn ensure_group(state: &AppState, name: &str) -> Result<Uuid, ApiError> {
    let rec = sqlx::query(
        "INSERT INTO groups (id, name) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(name)
    .fetch_optional(&state.pool)
    .await
    .map_err(db_err)?;

    if let Some(r) = rec {
        Ok(r.get::<Uuid, _>(0))
    } else {
        let existing: (Uuid,) = sqlx::query_as("SELECT id FROM groups WHERE name = $1")
            .bind(name)
            .fetch_one(&state.pool)
            .await
            .map_err(db_err)?;
        Ok(existing.0)
    }
}

async fn audit_log(
    state: &AppState,
    request_id: Uuid,
    actor_username: Option<&str>,
    device_id: Option<Uuid>,
    action: &str,
    target: &str,
    result: &str,
    reason: &str,
    details: Option<Value>,
) {
    let details_json: Option<SqlJson<Value>> = details.map(SqlJson);
    if let Err(err) = sqlx::query(
        r#"
        INSERT INTO audit_logs (request_id, actor_username, device_id, action, target, result, reason, details)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(request_id)
    .bind(actor_username)
    .bind(device_id)
    .bind(action)
    .bind(target)
    .bind(result)
    .bind(reason)
    .bind(details_json)
    .execute(&state.pool)
    .await
    {
        error!(error = %err, "failed to write audit log");
    }
}
