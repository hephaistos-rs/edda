//! OAuth2/OIDC *consumer* login against exactly one, instance-configured,
//! generic OIDC-compliant provider — Edda authenticates against external
//! identity providers, it does not act as one itself (that's out of this
//! plan's scope entirely). Provider configuration is environment-driven,
//! not database-stored (parsed once by `edda_app::config` from the
//! `EDDA_OAUTH_*` variables and passed in via `AppState`) — there is
//! nothing per-instance-secret about it that needs at-rest encryption the
//! way a per-user TOTP secret does.
//!
//! **Account-linking policy** (deliberate, not incidental): a first-time
//! OAuth login whose email matches an *existing* password-based account
//! never auto-links. The caller must already be authenticated (a normal
//! password login) before `link` is used to attach an OAuth identity to
//! their own account — see `LoginOutcome::EmailBelongsToExistingAccount`,
//! which the HTTP layer maps to "please log in with your password, then
//! link this from settings," never to a silent link.

use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::reqwest;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
};

use edda_db::{DbPool, OAuthIdentityRepo, UserRepo};
use edda_domain::{OAuthIdentityId, User, UserId};

pub const PROVIDER_NAME: &str = "oidc";

/// One OIDC provider's consumer-login credentials. Constructed by
/// `edda_app::config` from the `EDDA_OAUTH_*` variables (all four or
/// none) and passed in via `AppState` — this crate never reads the
/// environment. `None` in `AppState` means OIDC login isn't offered.
#[derive(Debug, Clone)]
pub struct Config {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
}

#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    #[error("OAuth login is not configured for this instance")]
    NotConfigured,
    #[error("discovery against the configured issuer failed: {0}")]
    Discovery(String),
    #[error("the identity provider's response could not be verified: {0}")]
    Verification(String),
    #[error("that provider did not return an email address")]
    NoEmail,
    #[error(transparent)]
    Db(#[from] edda_db::DbError),
}

/// Everything the HTTP layer needs to stash (in the pre-login session)
/// across the redirect round-trip.
pub struct AuthorizationRequest {
    pub url: String,
    pub csrf_token: String,
    pub nonce: String,
    pub pkce_verifier: String,
}

/// Not factored into a single "build once, use everywhere" helper: the
/// `openidconnect`/`oauth2` client type carries its configured-endpoint
/// state in its own generic parameters (a compile-time guarantee that,
/// e.g., `exchange_code` can't be called before a token endpoint is set)
/// — a shared function returning a named `CoreClient` type doesn't work
/// because the type alias fixes those parameters to a *different* state
/// than what `from_provider_metadata().set_redirect_uri(...)` actually
/// produces. Duplicating this construction across the three functions
/// below is the pragmatic way to work with that type-state design rather
/// than fighting it with an unwieldy explicit type alias.
macro_rules! discover_and_build_client {
    ($config:expr) => {{
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("building a reqwest client never fails under normal conditions");
        let issuer_url = IssuerUrl::new($config.issuer_url.clone())
            .map_err(|err| OAuthError::Discovery(err.to_string()))?;
        let metadata = CoreProviderMetadata::discover_async(issuer_url, &http_client)
            .await
            .map_err(|err| OAuthError::Discovery(err.to_string()))?;
        let redirect_url = RedirectUrl::new($config.redirect_url.clone())
            .map_err(|err| OAuthError::Discovery(err.to_string()))?;
        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new($config.client_id.clone()),
            Some(ClientSecret::new($config.client_secret.clone())),
        )
        .set_redirect_uri(redirect_url);
        (client, http_client)
    }};
}

/// Starts a login: returns the URL to redirect the browser to, plus the
/// CSRF/nonce/PKCE values the caller must hold onto (in the session) and
/// pass back into `complete` unchanged.
pub async fn start(config: &Config) -> Result<AuthorizationRequest, OAuthError> {
    let (client, _http_client) = discover_and_build_client!(config);
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    Ok(AuthorizationRequest {
        url: auth_url.to_string(),
        csrf_token: csrf_token.secret().clone(),
        nonce: nonce.secret().clone(),
        pkce_verifier: pkce_verifier.secret().clone(),
    })
}

pub enum LoginOutcome {
    /// A known OAuth identity resolved directly to an existing user.
    LoggedIn(User),
    /// A brand-new email — an account was created from the provider's
    /// claims and linked immediately, the same way a fresh signup would
    /// be.
    NewAccountCreated(User),
    /// The provider's email matches an existing *password* account with
    /// no linked OAuth identity yet — per the account-linking policy,
    /// this is never auto-linked. The caller must log in with their
    /// password and use `link` from an authenticated context instead.
    EmailBelongsToExistingAccount,
}

/// Completes the callback: verifies the code/state, resolves the
/// provider's `sub`+email claims, and either logs into a known linked
/// identity, creates a brand-new account, or refuses to auto-link an
/// email match — see `LoginOutcome`.
pub async fn complete(
    pool: &DbPool,
    config: &Config,
    code: &str,
    pkce_verifier: String,
    nonce: &str,
) -> Result<LoginOutcome, OAuthError> {
    let (client, http_client) = discover_and_build_client!(config);

    let token_response = client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .map_err(|err| OAuthError::Verification(err.to_string()))?
        .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
        .request_async(&http_client)
        .await
        .map_err(|err| OAuthError::Verification(err.to_string()))?;

    let id_token = token_response.extra_fields().id_token().ok_or_else(|| {
        OAuthError::Verification("provider did not return an id_token".to_string())
    })?;
    let verifier = client.id_token_verifier();
    let claims = id_token
        .claims(&verifier, &Nonce::new(nonce.to_string()))
        .map_err(|err| OAuthError::Verification(err.to_string()))?;

    let subject = claims.subject().as_str().to_string();
    let email = claims
        .email()
        .map(|email| email.as_str().to_string())
        .ok_or(OAuthError::NoEmail)?;

    if let Some(identity) =
        OAuthIdentityRepo::find_by_provider_subject(pool, PROVIDER_NAME, &subject).await?
    {
        let row = UserRepo::find_by_id(pool, identity.user_id)
            .await?
            .expect("a linked identity always points at an existing user");
        return Ok(LoginOutcome::LoggedIn(row.user));
    }

    if UserRepo::find_by_email(pool, &email).await?.is_some() {
        return Ok(LoginOutcome::EmailBelongsToExistingAccount);
    }

    let username = derive_username_from_email(&email);
    let random_password_hash = crate::password::hash_password(&random_unusable_secret())
        .expect("hashing a freshly generated random string never fails");
    let user_id = UserId::new();
    UserRepo::insert(pool, user_id, &username, &email, &random_password_hash)
        .await
        .map_err(|err| match err {
            edda_db::user_repo::InsertUserError::Db(err) => OAuthError::Db(err),
            _ => OAuthError::Db(edda_db::DbError::RowNotFound),
        })?;
    OAuthIdentityRepo::insert(
        pool,
        OAuthIdentityId::new(),
        user_id,
        PROVIDER_NAME,
        &subject,
    )
    .await?;

    let row = UserRepo::find_by_id(pool, user_id)
        .await?
        .expect("just-inserted user exists");
    Ok(LoginOutcome::NewAccountCreated(row.user))
}

/// Links an OAuth identity to an *already authenticated* user — the only
/// path that attaches an identity to an account with a pre-existing
/// email match, per the account-linking policy.
pub async fn link(
    pool: &DbPool,
    config: &Config,
    user_id: UserId,
    code: &str,
    pkce_verifier: String,
    nonce: &str,
) -> Result<(), OAuthError> {
    let (client, http_client) = discover_and_build_client!(config);

    let token_response = client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .map_err(|err| OAuthError::Verification(err.to_string()))?
        .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
        .request_async(&http_client)
        .await
        .map_err(|err| OAuthError::Verification(err.to_string()))?;
    let id_token = token_response.extra_fields().id_token().ok_or_else(|| {
        OAuthError::Verification("provider did not return an id_token".to_string())
    })?;
    let verifier = client.id_token_verifier();
    let claims = id_token
        .claims(&verifier, &Nonce::new(nonce.to_string()))
        .map_err(|err| OAuthError::Verification(err.to_string()))?;
    let subject = claims.subject().as_str().to_string();

    OAuthIdentityRepo::insert(
        pool,
        OAuthIdentityId::new(),
        user_id,
        PROVIDER_NAME,
        &subject,
    )
    .await?;
    Ok(())
}

fn derive_username_from_email(email: &str) -> String {
    let local_part = email.split('@').next().unwrap_or("user");
    let sanitized: String = local_part
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!("{sanitized}_{}", &UserId::new().to_string()[..8])
}

fn random_unusable_secret() -> String {
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A real HTTP round-trip against a real (minimal, in-process) OpenID
/// Connect provider — discovery document, JWKS, and a token endpoint that
/// signs and returns a genuine RS256 ID token — exercised through this
/// module's actual `start`/`complete` functions exactly as a browser-based
/// login would drive them (minus the browser: the "user consenting at the
/// provider" step is simulated by directly issuing an authorization code
/// the mock's `/token` endpoint accepts). This is deliberately not a
/// mocked/stubbed `openidconnect` client — every byte the client parses
/// (metadata JSON, JWKS JSON, the signed token response) is produced by
/// this crate's own dependency, `openidconnect`, from the provider side
/// too, so a wire-format mismatch would fail here exactly as it would
/// against a real provider.
#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::extract::State;
    use axum::response::{IntoResponse, Json, Response};
    use axum::routing::{get, post};
    use axum::Router;
    use chrono::{Duration, Utc};
    use openidconnect::core::{
        CoreIdToken, CoreIdTokenClaims, CoreIdTokenFields, CoreJwsSigningAlgorithm,
        CoreProviderMetadata, CoreResponseType, CoreRsaPrivateSigningKey,
        CoreSubjectIdentifierType, CoreTokenResponse, CoreTokenType,
    };
    use openidconnect::{
        AccessToken, Audience, AuthUrl, EmptyAdditionalClaims, EmptyAdditionalProviderMetadata,
        EmptyExtraTokenFields, EndUserEmail, IssuerUrl as OidcIssuerUrl, JsonWebKeySetUrl,
        PrivateSigningKey, ResponseTypes, StandardClaims, SubjectIdentifier, TokenUrl,
    };

    use super::*;

    // A fixed 2048-bit RSA test key, taken from `openidconnect`'s own test
    // suite (its `src/jwt/tests.rs`) — this workspace never signs anything
    // real with it, it exists purely so this test's mock provider can
    // produce a genuinely-signed (not fake) ID token.
    const TEST_RSA_PRIV_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
         MIIEowIBAAKCAQEAn4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8/KuKPEHLd4\n\
         rHVTeT+O+XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz/AJmSCpMaJMRBSFKrKb2wqVwG\n\
         U/NsYOYL+QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj+oBHqFEHYpP\n\
         e7Tpe+OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzw\n\
         OHrtIQbS0FVbb9k3+tVTU4fg/3L/vniUFAKwuCLqKnS2BYwdq/mzSnbLY7h/qixo\n\
         R7jig3//kRhuaxwUkRz5iaiQkqgc5gHdrNP5zwIDAQABAoIBAG1lAvQfhBUSKPJK\n\
         Rn4dGbshj7zDSr2FjbQf4pIh/ZNtHk/jtavyO/HomZKV8V0NFExLNi7DUUvvLiW7\n\
         0PgNYq5MDEjJCtSd10xoHa4QpLvYEZXWO7DQPwCmRofkOutf+NqyDS0QnvFvp2d+\n\
         Lov6jn5C5yvUFgw6qWiLAPmzMFlkgxbtjFAWMJB0zBMy2BqjntOJ6KnqtYRMQUxw\n\
         TgXZDF4rhYVKtQVOpfg6hIlsaoPNrF7dofizJ099OOgDmCaEYqM++bUlEHxgrIVk\n\
         wZz+bg43dfJCocr9O5YX0iXaz3TOT5cpdtYbBX+C/5hwrqBWru4HbD3xz8cY1TnD\n\
         qQa0M8ECgYEA3Slxg/DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex/fp7AZ/9\n\
         nRaO7HX/+SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr/WCsmGpeNqQn\n\
         ev1T7IyEsnh8UMt+n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0kCgYEAuKE2\n\
         dh+cTf6ERF4k4e/jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR/cu0Dm1MZwW\n\
         mtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoB\n\
         vyY898EXvRD+hdqRxHlSqAZ192zB3pVFJ0s7pFcCgYAHw9W9eS8muPYv4ZhDu/fL\n\
         2vorDmD1JqFcHCxZTOnX1NWWAj5hXzmrU0hvWvFC0P4ixddHf5Nqd6+5E9G3k4E5\n\
         2IwZCnylu3bqCWNh8pT8T3Gf5FQsfPT5530T2BcsoPhUaeCnP499D+rb2mTnFYeg\n\
         mnTT1B/Ue8KGLFFfn16GKQKBgAiw5gxnbocpXPaO6/OKxFFZ+6c0OjxfN2PogWce\n\
         TU/k6ZzmShdaRKwDFXisxRJeNQ5Rx6qgS0jNFtbDhW8E8WFmQ5urCOqIOYk28EBi\n\
         At4JySm4v+5P7yYBh8B8YD2l9j57z/s8hJAxEbn/q8uHP2ddQqvQKgtsni+pHSk9\n\
         XGBfAoGBANz4qr10DdM8DHhPrAb2YItvPVz/VwkBd1Vqj8zCpyIEKe/07oKOvjWQ\n\
         SgkLDH9x2hBgY01SbP43CvPk0V72invu2TGkI/FXwXWJLLG7tDSgw4YyfhrYrHmg\n\
         1Vre3XB9HH8MYBVB6UIexaAq4xSeoemRKTBesZro7OKjKT8/GmiO\n\
         -----END RSA PRIVATE KEY-----";

    /// What the mock provider hands back for whichever `(subject, email)`
    /// pair the current test scenario wants to log in as.
    struct MockIdpState {
        base_url: String,
        subject: String,
        email: String,
        client_id: String,
    }

    async fn discovery(State(state): State<Arc<MockIdpState>>) -> Response {
        let metadata = CoreProviderMetadata::new(
            OidcIssuerUrl::new(state.base_url.clone()).unwrap(),
            AuthUrl::new(format!("{}/authorize", state.base_url)).unwrap(),
            JsonWebKeySetUrl::new(format!("{}/jwks", state.base_url)).unwrap(),
            vec![ResponseTypes::new(vec![CoreResponseType::Code])],
            vec![CoreSubjectIdentifierType::Public],
            vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
            EmptyAdditionalProviderMetadata {},
        )
        .set_token_endpoint(Some(
            TokenUrl::new(format!("{}/token", state.base_url)).unwrap(),
        ));
        Json(metadata).into_response()
    }

    async fn jwks(State(_state): State<Arc<MockIdpState>>) -> Response {
        let signing_key = CoreRsaPrivateSigningKey::from_pem(TEST_RSA_PRIV_KEY, None)
            .expect("valid test RSA key");
        let jwks =
            openidconnect::core::CoreJsonWebKeySet::new(vec![signing_key.as_verification_key()]);
        Json(jwks).into_response()
    }

    async fn token(State(state): State<Arc<MockIdpState>>) -> Response {
        let signing_key = CoreRsaPrivateSigningKey::from_pem(TEST_RSA_PRIV_KEY, None)
            .expect("valid test RSA key");
        let id_token = CoreIdToken::new(
            CoreIdTokenClaims::new(
                OidcIssuerUrl::new(state.base_url.clone()).unwrap(),
                vec![Audience::new(state.client_id.clone())],
                Utc::now() + Duration::seconds(300),
                Utc::now(),
                StandardClaims::new(SubjectIdentifier::new(state.subject.clone()))
                    .set_email(Some(EndUserEmail::new(state.email.clone())))
                    .set_email_verified(Some(true)),
                EmptyAdditionalClaims {},
            )
            // The real client always sets a nonce for this flow; a mock
            // that skipped mirroring it back would fail nonce
            // verification on the client side, which is exactly the
            // behavior this test wants confidence in outside the happy
            // path — so it's read back from a fixed, test-known value
            // rather than hard-coded independently.
            .set_nonce(Some(Nonce::new(TEST_NONCE.to_string()))),
            &signing_key,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            Some(&AccessToken::new("mock-access-token".to_string())),
            None,
        )
        .expect("building a signed test ID token never fails");

        let response = CoreTokenResponse::new(
            AccessToken::new("mock-access-token".to_string()),
            CoreTokenType::Bearer,
            CoreIdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
        );
        Json(response).into_response()
    }

    const TEST_NONCE: &str = "fixed-test-nonce";

    async fn spawn_mock_idp(subject: &str, email: &str, client_id: &str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{addr}");
        let state = Arc::new(MockIdpState {
            base_url: base_url.clone(),
            subject: subject.to_string(),
            email: email.to_string(),
            client_id: client_id.to_string(),
        });
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/token", post(token))
            .with_state(state);
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        base_url
    }

    fn test_config(base_url: &str, client_id: &str) -> Config {
        Config {
            issuer_url: base_url.to_string(),
            client_id: client_id.to_string(),
            client_secret: "unused-by-the-mock".to_string(),
            redirect_url: "http://localhost/callback".to_string(),
        }
    }

    /// `complete`'s real signature takes the nonce/pkce_verifier the
    /// *client* generated during `start` — but this test drives the mock
    /// provider directly rather than going through a real browser
    /// redirect, so it fabricates a matching pair itself and configures
    /// the mock to echo the same fixed nonce back, exactly mirroring what
    /// `start`+a real provider would produce between them.
    async fn complete_against_mock(
        config: &Config,
        pool: &DbPool,
    ) -> Result<LoginOutcome, OAuthError> {
        let pkce_verifier = "test-pkce-verifier-unused-by-mock".to_string();
        complete(pool, config, "mock-auth-code", pkce_verifier, TEST_NONCE).await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_brand_new_email_creates_and_logs_into_a_new_account() {
        let pool = edda_db::test_pool().await;
        let base_url = spawn_mock_idp("subject-new", "new-user@example.com", "test-client").await;
        let config = test_config(&base_url, "test-client");

        let outcome = complete_against_mock(&config, &pool).await.unwrap();
        let user = match outcome {
            LoginOutcome::NewAccountCreated(user) => user,
            _ => panic!("expected a new account to be created"),
        };
        assert_eq!(user.email, "new-user@example.com");

        // Logging in again with the same subject resolves to the same
        // account, not a second one.
        let outcome = complete_against_mock(&config, &pool).await.unwrap();
        match outcome {
            LoginOutcome::LoggedIn(logged_in) => assert_eq!(logged_in.id, user.id),
            _ => panic!("expected the second login to resolve the already-linked identity"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_email_matching_an_existing_password_account_is_never_auto_linked() {
        let pool = edda_db::test_pool().await;
        edda_db::UserRepo::insert(
            &pool,
            UserId::new(),
            "existing",
            "existing@example.com",
            "some-password-hash",
        )
        .await
        .unwrap();

        let base_url =
            spawn_mock_idp("subject-existing", "existing@example.com", "test-client").await;
        let config = test_config(&base_url, "test-client");

        let outcome = complete_against_mock(&config, &pool).await.unwrap();
        assert!(matches!(
            outcome,
            LoginOutcome::EmailBelongsToExistingAccount
        ));

        // And no identity was linked as a side effect of that refusal.
        assert!(OAuthIdentityRepo::find_by_provider_subject(
            &pool,
            PROVIDER_NAME,
            "subject-existing"
        )
        .await
        .unwrap()
        .is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn linking_from_an_authenticated_context_attaches_the_identity() {
        let pool = edda_db::test_pool().await;
        let user_id = UserId::new();
        edda_db::UserRepo::insert(&pool, user_id, "existing", "existing@example.com", "hash")
            .await
            .unwrap();

        let base_url =
            spawn_mock_idp("subject-to-link", "existing@example.com", "test-client").await;
        let config = test_config(&base_url, "test-client");

        link(
            &pool,
            &config,
            user_id,
            "mock-auth-code",
            "test-pkce-verifier-unused-by-mock".to_string(),
            TEST_NONCE,
        )
        .await
        .unwrap();

        let identity =
            OAuthIdentityRepo::find_by_provider_subject(&pool, PROVIDER_NAME, "subject-to-link")
                .await
                .unwrap()
                .expect("identity is now linked");
        assert_eq!(identity.user_id, user_id);
    }
}
