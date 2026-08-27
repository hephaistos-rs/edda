//! Integration-style tests against a real (in-memory) SQLite database.
//! See `edda-domain`'s own test module for the pure-authorization-
//! decision tests this crate deliberately doesn't duplicate (this module
//! tests persistence and schema behavior, not authorization policy).

use edda_domain::{
    effective_repo_role, AccessSubject, CloseReason, DiffAnchor, IssueState, LfsLockId,
    MergeStrategy, MilestoneState, PrRef, PrState, RepoRole, Repository, RepositoryId,
    RepositoryOwner, ReviewState, SshKeyId, TeamPermission, TeamUnit, User, UserId, Visibility,
};

use crate::{
    AccessTokenRepo, AuditEventRepo, BranchProtectionRepo, IssueCommentRepo, IssueRepo, LabelRepo,
    LfsRepo, MilestoneRepo, OAuthIdentityRepo, OrganizationRepo, PrCommentRepo, PrReviewRepo,
    PullRequestRepo, RepoAccessRepo, RepositoryRepo, SshKeyRepo, TeamMemberRepo, TeamRepo,
    TotpRepo, UserRepo, WebauthnRepo,
};

async fn insert_user(pool: &crate::DbPool, username: &str) -> UserId {
    let id = UserId::new();
    UserRepo::insert(pool, id, username, &format!("{username}@example.com"), "x")
        .await
        .unwrap();
    id
}

/// Opens a pull request with a fixed `main` target and no body, varying
/// only title/source branch/author — what every PR-related test below
/// needs to set the scene, before exercising whatever it's actually
/// testing.
async fn open_pr(
    pool: &crate::DbPool,
    repository_id: RepositoryId,
    id: edda_domain::PullRequestId,
    title: &str,
    source_branch: &str,
    author_id: UserId,
) -> i64 {
    PullRequestRepo::insert(
        pool,
        id,
        repository_id,
        crate::NewPullRequest {
            title,
            body: None,
            author_id,
            source: &PrRef {
                repository_id,
                branch: source_branch.to_string(),
            },
            target: "main",
            draft: false,
        },
    )
    .await
    .unwrap()
}

fn repo(owner: UserId, name: &str, visibility: Visibility) -> Repository {
    Repository {
        id: RepositoryId::new(),
        owner: RepositoryOwner::User(owner),
        name: name.to_string(),
        description: None,
        visibility,
        forked_from: None,
    }
}

#[tokio::test]
async fn a_repository_name_is_only_unique_per_owner() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let bob = insert_user(&pool, "bob").await;

    RepositoryRepo::insert(&pool, &repo(alice, "shared", Visibility::Public))
        .await
        .unwrap();
    RepositoryRepo::insert(&pool, &repo(bob, "shared", Visibility::Public))
        .await
        .unwrap();

    let err = RepositoryRepo::insert(&pool, &repo(alice, "shared", Visibility::Public))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        crate::repository_repo::InsertRepositoryError::AlreadyExists(_)
    ));
}

#[tokio::test]
async fn access_grants_are_keyed_by_the_specific_repository_not_just_its_name() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let bob = insert_user(&pool, "bob").await;

    let alice_repo = repo(alice, "shared", Visibility::Public);
    let bob_repo = repo(bob, "shared", Visibility::Public);
    RepositoryRepo::insert(&pool, &alice_repo).await.unwrap();
    RepositoryRepo::insert(&pool, &bob_repo).await.unwrap();

    RepoAccessRepo::grant_owner(&pool, alice_repo.id, AccessSubject::User(alice))
        .await
        .unwrap();
    RepoAccessRepo::grant_owner(&pool, bob_repo.id, AccessSubject::User(bob))
        .await
        .unwrap();

    assert_eq!(
        RepoAccessRepo::find(&pool, alice_repo.id, AccessSubject::User(alice))
            .await
            .unwrap()
            .unwrap()
            .role,
        RepoRole::Owner
    );
    assert!(
        RepoAccessRepo::find(&pool, bob_repo.id, AccessSubject::User(alice))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_collaborator_grant_can_be_added_and_removed_but_the_owner_grant_cannot() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let carol = insert_user(&pool, "carol").await;

    let alice_repo = repo(alice, "shared", Visibility::Private);
    RepositoryRepo::insert(&pool, &alice_repo).await.unwrap();
    RepoAccessRepo::grant_owner(&pool, alice_repo.id, AccessSubject::User(alice))
        .await
        .unwrap();
    RepoAccessRepo::grant(
        &pool,
        alice_repo.id,
        AccessSubject::User(carol),
        RepoRole::Write,
    )
    .await
    .unwrap();

    assert_eq!(
        RepoAccessRepo::find(&pool, alice_repo.id, AccessSubject::User(carol))
            .await
            .unwrap()
            .unwrap()
            .role,
        RepoRole::Write
    );

    let removed = RepoAccessRepo::remove_grant(&pool, alice_repo.id, AccessSubject::User(carol))
        .await
        .unwrap();
    assert!(removed);
    assert!(
        RepoAccessRepo::find(&pool, alice_repo.id, AccessSubject::User(carol))
            .await
            .unwrap()
            .is_none()
    );

    // The owner grant is structurally protected — `remove_grant`'s own
    // `role != 'owner'` clause is what's under test here, independent of
    // any authorization-layer check.
    let removed_owner =
        RepoAccessRepo::remove_grant(&pool, alice_repo.id, AccessSubject::User(alice))
            .await
            .unwrap();
    assert!(!removed_owner);
    assert_eq!(
        RepoAccessRepo::find(&pool, alice_repo.id, AccessSubject::User(alice))
            .await
            .unwrap()
            .unwrap()
            .role,
        RepoRole::Owner
    );
}

#[tokio::test]
async fn deleting_a_repository_cascades_its_access_grants() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let bob = insert_user(&pool, "bob").await;

    let alice_repo = repo(alice, "shared", Visibility::Private);
    RepositoryRepo::insert(&pool, &alice_repo).await.unwrap();
    RepoAccessRepo::grant_owner(&pool, alice_repo.id, AccessSubject::User(alice))
        .await
        .unwrap();
    RepoAccessRepo::grant(
        &pool,
        alice_repo.id,
        AccessSubject::User(bob),
        RepoRole::Write,
    )
    .await
    .unwrap();

    RepositoryRepo::delete(&pool, alice_repo.id).await.unwrap();

    // Repo-access rows are removed by `repo_access`'s `ON DELETE CASCADE`
    // foreign key, not a separate cleanup call — nothing in this test
    // calls anything access-specific after `delete`.
    assert!(
        RepoAccessRepo::find(&pool, alice_repo.id, AccessSubject::User(alice))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        RepoAccessRepo::find(&pool, alice_repo.id, AccessSubject::User(bob))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn signup_style_username_and_email_collisions_are_reported_distinctly() {
    let pool = crate::test_pool().await;
    insert_user(&pool, "alice").await;

    let err = UserRepo::insert(
        &pool,
        UserId::new(),
        "alice",
        "someone-else@example.com",
        "x",
    )
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        crate::user_repo::InsertUserError::UsernameTaken
    ));

    let err = UserRepo::insert(
        &pool,
        UserId::new(),
        "someone-else",
        "alice@example.com",
        "x",
    )
    .await
    .unwrap_err();
    assert!(matches!(err, crate::user_repo::InsertUserError::EmailTaken));
}

#[tokio::test]
async fn an_access_token_authenticates_back_to_its_owning_user_and_scope() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;

    AccessTokenRepo::insert(
        &pool,
        edda_domain::AccessTokenId::new(),
        alice,
        "laptop",
        "deadbeef",
        &edda_domain::RepositoryScope::All,
    )
    .await
    .unwrap();

    let (user, scope): (User, edda_domain::RepositoryScope) =
        AccessTokenRepo::find_by_hash(&pool, "deadbeef")
            .await
            .unwrap()
            .unwrap();
    assert_eq!(user.id, alice);
    assert_eq!(scope, edda_domain::RepositoryScope::All);

    assert!(AccessTokenRepo::find_by_hash(&pool, "not-a-real-hash")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn an_ssh_key_resolves_back_to_its_owning_user() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;

    SshKeyRepo::insert(
        &pool,
        SshKeyId::new(),
        alice,
        "SHA256:deadbeef",
        "ssh-ed25519 AAAA... laptop",
        "laptop",
    )
    .await
    .unwrap();

    let user = SshKeyRepo::find_by_fingerprint(&pool, "SHA256:deadbeef")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.id, alice);

    assert!(
        SshKeyRepo::find_by_fingerprint(&pool, "SHA256:not-registered")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn the_same_fingerprint_cannot_be_registered_twice() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let bob = insert_user(&pool, "bob").await;

    SshKeyRepo::insert(
        &pool,
        SshKeyId::new(),
        alice,
        "SHA256:shared",
        "ssh-ed25519 AAAA... k1",
        "k1",
    )
    .await
    .unwrap();
    let err = SshKeyRepo::insert(
        &pool,
        SshKeyId::new(),
        bob,
        "SHA256:shared",
        "ssh-ed25519 AAAA... k2",
        "k2",
    )
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        crate::ssh_key_repo::InsertSshKeyError::FingerprintTaken
    ));
}

#[tokio::test]
async fn revoking_an_ssh_key_is_scoped_to_its_owner() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let bob = insert_user(&pool, "bob").await;

    let key_id = SshKeyId::new();
    SshKeyRepo::insert(
        &pool,
        key_id,
        alice,
        "SHA256:alice-key",
        "ssh-ed25519 AAAA... k",
        "k",
    )
    .await
    .unwrap();

    // Bob can't revoke Alice's key by guessing its id.
    assert!(!SshKeyRepo::revoke(&pool, bob, key_id).await.unwrap());
    assert!(SshKeyRepo::find_by_fingerprint(&pool, "SHA256:alice-key")
        .await
        .unwrap()
        .is_some());

    assert!(SshKeyRepo::revoke(&pool, alice, key_id).await.unwrap());
    assert!(SshKeyRepo::find_by_fingerprint(&pool, "SHA256:alice-key")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn deleting_a_user_cascades_their_ssh_keys() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    SshKeyRepo::insert(
        &pool,
        SshKeyId::new(),
        alice,
        "SHA256:alice-key",
        "ssh-ed25519 AAAA... k",
        "k",
    )
    .await
    .unwrap();

    let alice_id_text = alice.to_string();
    let sql = match pool.backend {
        crate::Backend::Postgres => "DELETE FROM users WHERE id = $1",
        crate::Backend::Sqlite | crate::Backend::MySql => "DELETE FROM users WHERE id = ?",
    };
    sqlx::query(sql)
        .bind(&alice_id_text)
        .execute(&pool.any)
        .await
        .unwrap();

    assert!(SshKeyRepo::find_by_fingerprint(&pool, "SHA256:alice-key")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn a_fork_persists_and_round_trips_its_forked_from_pointer() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let bob = insert_user(&pool, "bob").await;

    let source = repo(alice, "upstream", Visibility::Public);
    RepositoryRepo::insert(&pool, &source).await.unwrap();

    let mut fork = repo(bob, "upstream", Visibility::Public);
    fork.forked_from = Some(source.id);
    RepositoryRepo::insert_with_owner(&pool, &fork, bob)
        .await
        .unwrap();

    let found = RepositoryRepo::find_by_id(&pool, fork.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.forked_from, Some(source.id));

    let found_source = RepositoryRepo::find_by_id(&pool, source.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found_source.forked_from, None);
}

#[tokio::test]
async fn an_lfs_object_round_trips_by_repository_and_oid() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let repository = repo(alice, "assets", Visibility::Public);
    RepositoryRepo::insert(&pool, &repository).await.unwrap();

    let oid = "a".repeat(64);
    assert!(LfsRepo::find_object(&pool, repository.id, &oid)
        .await
        .unwrap()
        .is_none());

    LfsRepo::insert_object(&pool, repository.id, &oid, 5000, "aa/aa/aaaa")
        .await
        .unwrap();

    let found = LfsRepo::find_object(&pool, repository.id, &oid)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.size_bytes, 5000);
    assert_eq!(found.storage_key, "aa/aa/aaaa");

    // Content-addressed and immutable — inserting the same (repository,
    // oid) again is a harmless no-op, not a conflict error.
    LfsRepo::insert_object(&pool, repository.id, &oid, 5000, "aa/aa/aaaa")
        .await
        .unwrap();
}

#[tokio::test]
async fn an_lfs_lock_blocks_a_second_lock_on_the_same_path_until_released() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let bob = insert_user(&pool, "bob").await;
    let repository = repo(alice, "assets", Visibility::Public);
    RepositoryRepo::insert(&pool, &repository).await.unwrap();

    let lock_id = LfsLockId::new();
    LfsRepo::create_lock(&pool, lock_id, repository.id, "asset.psd", alice)
        .await
        .unwrap();

    let err = LfsRepo::create_lock(&pool, LfsLockId::new(), repository.id, "asset.psd", bob)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        crate::lfs_repo::CreateLockError::AlreadyLocked(_)
    ));

    let locks = LfsRepo::list_locks(&pool, repository.id).await.unwrap();
    assert_eq!(locks.len(), 1);
    assert_eq!(locks[0].owner_id, alice);

    assert!(LfsRepo::delete_lock(&pool, lock_id).await.unwrap());
    assert!(LfsRepo::list_locks(&pool, repository.id)
        .await
        .unwrap()
        .is_empty());

    // Now that it's released, someone else can take the same path.
    LfsRepo::create_lock(&pool, LfsLockId::new(), repository.id, "asset.psd", bob)
        .await
        .unwrap();
}

#[tokio::test]
async fn an_oauth_identity_resolves_back_to_its_linked_user() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;

    OAuthIdentityRepo::insert(
        &pool,
        edda_domain::OAuthIdentityId::new(),
        alice,
        "test-idp",
        "sub-123",
    )
    .await
    .unwrap();

    let identity = OAuthIdentityRepo::find_by_provider_subject(&pool, "test-idp", "sub-123")
        .await
        .unwrap()
        .expect("identity round-trips");
    assert_eq!(identity.user_id, alice);

    assert!(
        OAuthIdentityRepo::find_by_provider_subject(&pool, "test-idp", "no-such-subject")
            .await
            .unwrap()
            .is_none()
    );

    let identities = OAuthIdentityRepo::list_for_user(&pool, alice)
        .await
        .unwrap();
    assert_eq!(identities.len(), 1);

    assert!(OAuthIdentityRepo::delete(&pool, alice, identity.id)
        .await
        .unwrap());
    assert!(OAuthIdentityRepo::list_for_user(&pool, alice)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn a_totp_secret_is_not_activated_until_activate_is_called() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;

    assert!(!TotpRepo::is_activated(&pool, alice).await.unwrap());

    TotpRepo::upsert_secret(&pool, alice, b"ciphertext-bytes")
        .await
        .unwrap();
    assert!(!TotpRepo::is_activated(&pool, alice).await.unwrap());

    let (stored, activated_at) = TotpRepo::find_by_user(&pool, alice)
        .await
        .unwrap()
        .expect("secret round-trips");
    assert_eq!(stored, b"ciphertext-bytes");
    assert!(activated_at.is_none());

    TotpRepo::activate(&pool, alice).await.unwrap();
    assert!(TotpRepo::is_activated(&pool, alice).await.unwrap());
}

#[tokio::test]
async fn a_totp_recovery_code_can_only_be_consumed_once() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;

    TotpRepo::replace_recovery_codes(&pool, alice, &["hash-a".to_string(), "hash-b".to_string()])
        .await
        .unwrap();

    assert!(TotpRepo::consume_recovery_code(&pool, alice, "hash-a")
        .await
        .unwrap());
    assert!(!TotpRepo::consume_recovery_code(&pool, alice, "hash-a")
        .await
        .unwrap());
    assert!(
        !TotpRepo::consume_recovery_code(&pool, alice, "no-such-hash")
            .await
            .unwrap()
    );
    assert!(TotpRepo::consume_recovery_code(&pool, alice, "hash-b")
        .await
        .unwrap());
}

#[tokio::test]
async fn disabling_totp_removes_the_secret_and_every_recovery_code() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;

    TotpRepo::upsert_secret(&pool, alice, b"ciphertext-bytes")
        .await
        .unwrap();
    TotpRepo::replace_recovery_codes(&pool, alice, &["hash-a".to_string()])
        .await
        .unwrap();
    TotpRepo::activate(&pool, alice).await.unwrap();

    TotpRepo::delete(&pool, alice).await.unwrap();

    assert!(TotpRepo::find_by_user(&pool, alice)
        .await
        .unwrap()
        .is_none());
    assert!(!TotpRepo::consume_recovery_code(&pool, alice, "hash-a")
        .await
        .unwrap());
}

#[tokio::test]
async fn a_webauthn_credential_round_trips_and_can_be_revoked_by_its_owner() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let bob = insert_user(&pool, "bob").await;

    let id = edda_domain::WebauthnCredentialId::new();
    WebauthnRepo::insert(&pool, id, alice, "laptop", "{\"fake\":\"passkey\"}")
        .await
        .unwrap();

    let creds = WebauthnRepo::list_for_user(&pool, alice).await.unwrap();
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].label, "laptop");
    assert!(creds[0].last_used_at.is_none());

    WebauthnRepo::update_passkey(&pool, id, "{\"fake\":\"updated\"}")
        .await
        .unwrap();
    let creds = WebauthnRepo::list_for_user(&pool, alice).await.unwrap();
    assert!(creds[0].last_used_at.is_some());

    // Bob can't revoke Alice's credential by guessing its id.
    assert!(!WebauthnRepo::delete(&pool, bob, id).await.unwrap());
    assert!(WebauthnRepo::delete(&pool, alice, id).await.unwrap());
}

#[tokio::test]
async fn audit_events_list_most_recent_first() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;

    AuditEventRepo::insert(
        &pool,
        edda_domain::AuditEventId::new(),
        "auth.login.success",
        Some(&alice.to_string()),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    AuditEventRepo::insert(
        &pool,
        edda_domain::AuditEventId::new(),
        "auth.token.create",
        Some(&alice.to_string()),
        Some("access_token"),
        None,
        Some("{\"name\":\"ci\"}"),
    )
    .await
    .unwrap();

    let events = AuditEventRepo::list_recent(&pool, 10).await.unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event_type, "auth.token.create");
    assert_eq!(events[1].event_type, "auth.login.success");
}

// --- pull requests, issues, labels, milestones, branch protection ---

#[tokio::test]
async fn pull_requests_and_issues_share_one_numbering_sequence_per_repository() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let repository = repo(alice, "demo", Visibility::Public);
    RepositoryRepo::insert(&pool, &repository).await.unwrap();

    let pr_number = open_pr(
        &pool,
        repository.id,
        edda_domain::PullRequestId::new(),
        "Add feature",
        "feature",
        alice,
    )
    .await;
    let issue_number = IssueRepo::insert(
        &pool,
        edda_domain::IssueId::new(),
        repository.id,
        "Bug report",
        None,
        alice,
    )
    .await
    .unwrap();
    let second_pr_number = open_pr(
        &pool,
        repository.id,
        edda_domain::PullRequestId::new(),
        "Fix bug",
        "fix",
        alice,
    )
    .await;

    assert_eq!(pr_number, 1);
    assert_eq!(issue_number, 2);
    assert_eq!(second_pr_number, 3);
}

#[tokio::test]
async fn a_pull_request_round_trips_through_open_and_merged_states() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let repository = repo(alice, "demo", Visibility::Public);
    RepositoryRepo::insert(&pool, &repository).await.unwrap();

    let id = edda_domain::PullRequestId::new();
    PullRequestRepo::insert(
        &pool,
        id,
        repository.id,
        crate::NewPullRequest {
            title: "Add feature",
            body: Some("Some body"),
            author_id: alice,
            source: &PrRef {
                repository_id: repository.id,
                branch: "feature".to_string(),
            },
            target: "main",
            draft: false,
        },
    )
    .await
    .unwrap();

    let pr = PullRequestRepo::find_by_id(&pool, id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pr.state, PrState::Open);
    assert_eq!(pr.title, "Add feature");
    assert_eq!(pr.body.as_deref(), Some("Some body"));
    assert_eq!(pr.source.branch, "feature");
    assert_eq!(pr.target, "main");

    let merged_state = PrState::Merged {
        merged_at: 12345,
        merge_commit: "a".repeat(40),
        strategy: MergeStrategy::Merge,
    };
    PullRequestRepo::update_state(&pool, id, &merged_state)
        .await
        .unwrap();

    let pr = PullRequestRepo::find_by_id(&pool, id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pr.state, merged_state);

    let by_number = PullRequestRepo::find_by_repository_and_number(&pool, repository.id, pr.number)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_number.id, id);
}

#[tokio::test]
async fn pr_reviews_are_appended_not_overwritten_and_list_in_order() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let bob = insert_user(&pool, "bob").await;
    let repository = repo(alice, "demo", Visibility::Public);
    RepositoryRepo::insert(&pool, &repository).await.unwrap();
    let pr_id = edda_domain::PullRequestId::new();
    open_pr(&pool, repository.id, pr_id, "Add feature", "feature", alice).await;

    PrReviewRepo::insert(
        &pool,
        edda_domain::PrReviewId::new(),
        pr_id,
        bob,
        ReviewState::ChangesRequested,
        Some("please fix"),
    )
    .await
    .unwrap();
    PrReviewRepo::insert(
        &pool,
        edda_domain::PrReviewId::new(),
        pr_id,
        bob,
        ReviewState::Approved,
        None,
    )
    .await
    .unwrap();

    let reviews = PrReviewRepo::list_for_pull_request(&pool, pr_id)
        .await
        .unwrap();
    assert_eq!(reviews.len(), 2);
    let latest = edda_domain::latest_reviews(&reviews);
    assert_eq!(latest.len(), 1);
    assert_eq!(latest[0].state, ReviewState::Approved);
}

#[tokio::test]
async fn a_pr_comment_can_be_anchored_to_a_diff_line_or_left_general() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let repository = repo(alice, "demo", Visibility::Public);
    RepositoryRepo::insert(&pool, &repository).await.unwrap();
    let pr_id = edda_domain::PullRequestId::new();
    open_pr(&pool, repository.id, pr_id, "Add feature", "feature", alice).await;

    PrCommentRepo::insert(
        &pool,
        edda_domain::PrCommentId::new(),
        pr_id,
        alice,
        "general comment",
        None,
    )
    .await
    .unwrap();
    let anchor = DiffAnchor {
        file_path: "src/main.rs".to_string(),
        line_range: (10, 12),
        commit_sha: "b".repeat(40),
    };
    PrCommentRepo::insert(
        &pool,
        edda_domain::PrCommentId::new(),
        pr_id,
        alice,
        "anchored comment",
        Some(&anchor),
    )
    .await
    .unwrap();

    let comments = PrCommentRepo::list_for_pull_request(&pool, pr_id)
        .await
        .unwrap();
    assert_eq!(comments.len(), 2);
    assert_eq!(comments[0].anchor, None);
    assert_eq!(comments[1].anchor.as_ref(), Some(&anchor));
}

#[tokio::test]
async fn applying_a_scoped_label_unapplies_the_previous_one_in_that_scope() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let repository = repo(alice, "demo", Visibility::Public);
    RepositoryRepo::insert(&pool, &repository).await.unwrap();
    let issue_id = edda_domain::IssueId::new();
    IssueRepo::insert(&pool, issue_id, repository.id, "Bug", None, alice)
        .await
        .unwrap();

    let low_id = edda_domain::LabelId::new();
    LabelRepo::insert(
        &pool,
        low_id,
        repository.id,
        "priority/low",
        "#00ff00",
        None,
    )
    .await
    .unwrap();
    let high_id = edda_domain::LabelId::new();
    LabelRepo::insert(
        &pool,
        high_id,
        repository.id,
        "priority/high",
        "#ff0000",
        None,
    )
    .await
    .unwrap();
    let bug_id = edda_domain::LabelId::new();
    LabelRepo::insert(&pool, bug_id, repository.id, "bug", "#0000ff", None)
        .await
        .unwrap();

    let low = LabelRepo::list_for_repository(&pool, repository.id)
        .await
        .unwrap()
        .into_iter()
        .find(|l| l.id == low_id)
        .unwrap();
    let high = LabelRepo::list_for_repository(&pool, repository.id)
        .await
        .unwrap()
        .into_iter()
        .find(|l| l.id == high_id)
        .unwrap();
    let bug = LabelRepo::list_for_repository(&pool, repository.id)
        .await
        .unwrap()
        .into_iter()
        .find(|l| l.id == bug_id)
        .unwrap();

    LabelRepo::apply_to_issue(&pool, issue_id, &low)
        .await
        .unwrap();
    LabelRepo::apply_to_issue(&pool, issue_id, &bug)
        .await
        .unwrap();
    let applied = LabelRepo::list_for_issue(&pool, issue_id).await.unwrap();
    assert_eq!(applied.len(), 2);

    // Applying `priority/high` unapplies `priority/low` (same scope) but
    // leaves the unscoped `bug` label untouched.
    LabelRepo::apply_to_issue(&pool, issue_id, &high)
        .await
        .unwrap();
    let applied = LabelRepo::list_for_issue(&pool, issue_id).await.unwrap();
    let applied_ids: std::collections::HashSet<_> = applied.iter().map(|l| l.id).collect();
    assert_eq!(applied_ids, [high_id, bug_id].into_iter().collect());
}

#[tokio::test]
async fn an_issue_can_be_assigned_a_milestone_and_closed() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let repository = repo(alice, "demo", Visibility::Public);
    RepositoryRepo::insert(&pool, &repository).await.unwrap();

    let milestone_id = edda_domain::MilestoneId::new();
    MilestoneRepo::insert(&pool, milestone_id, repository.id, "v1.0", None, None)
        .await
        .unwrap();

    let issue_id = edda_domain::IssueId::new();
    IssueRepo::insert(&pool, issue_id, repository.id, "Bug", None, alice)
        .await
        .unwrap();
    IssueRepo::set_milestone(&pool, issue_id, Some(milestone_id))
        .await
        .unwrap();

    let issue = IssueRepo::find_by_id(&pool, issue_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(issue.milestone_id, Some(milestone_id));
    assert_eq!(issue.state, IssueState::Open);

    IssueCommentRepo::insert(
        &pool,
        edda_domain::IssueCommentId::new(),
        issue_id,
        alice,
        "on it",
    )
    .await
    .unwrap();
    let comments = IssueCommentRepo::list_for_issue(&pool, issue_id)
        .await
        .unwrap();
    assert_eq!(comments.len(), 1);

    let closed_state = IssueState::Closed {
        closed_at: 999,
        reason: CloseReason::Completed,
    };
    IssueRepo::update_state(&pool, issue_id, &closed_state)
        .await
        .unwrap();
    let issue = IssueRepo::find_by_id(&pool, issue_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(issue.state, closed_state);

    MilestoneRepo::update_state(&pool, milestone_id, MilestoneState::Closed)
        .await
        .unwrap();
    let milestones = MilestoneRepo::list_for_repository(&pool, repository.id)
        .await
        .unwrap();
    assert_eq!(milestones[0].state, MilestoneState::Closed);
}

/// An issue can be created, labeled (including a scoped-label
/// mutual-exclusion check), commented on, and closed.
#[tokio::test]
async fn an_issue_can_be_created_labeled_commented_on_and_closed() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let repository = repo(alice, "demo", Visibility::Public);
    RepositoryRepo::insert(&pool, &repository).await.unwrap();

    // Created.
    let issue_id = edda_domain::IssueId::new();
    let number = IssueRepo::insert(
        &pool,
        issue_id,
        repository.id,
        "Something is broken",
        Some("Steps to reproduce..."),
        alice,
    )
    .await
    .unwrap();
    assert_eq!(number, 1);

    // Labeled — including the scoped mutual-exclusion check: applying
    // `priority/high` after `priority/low` replaces it, but leaves the
    // unscoped `bug` label alone.
    let bug_id = edda_domain::LabelId::new();
    LabelRepo::insert(&pool, bug_id, repository.id, "bug", "#ff0000", None)
        .await
        .unwrap();
    let low_id = edda_domain::LabelId::new();
    LabelRepo::insert(
        &pool,
        low_id,
        repository.id,
        "priority/low",
        "#00ff00",
        None,
    )
    .await
    .unwrap();
    let high_id = edda_domain::LabelId::new();
    LabelRepo::insert(
        &pool,
        high_id,
        repository.id,
        "priority/high",
        "#ffa500",
        None,
    )
    .await
    .unwrap();
    let repo_labels = LabelRepo::list_for_repository(&pool, repository.id)
        .await
        .unwrap();
    let find = |id| repo_labels.iter().find(|l| l.id == id).unwrap().clone();

    LabelRepo::apply_to_issue(&pool, issue_id, &find(bug_id))
        .await
        .unwrap();
    LabelRepo::apply_to_issue(&pool, issue_id, &find(low_id))
        .await
        .unwrap();
    let applied: std::collections::HashSet<_> = LabelRepo::list_for_issue(&pool, issue_id)
        .await
        .unwrap()
        .into_iter()
        .map(|l| l.id)
        .collect();
    assert_eq!(applied, [bug_id, low_id].into_iter().collect());

    LabelRepo::apply_to_issue(&pool, issue_id, &find(high_id))
        .await
        .unwrap();
    let applied: std::collections::HashSet<_> = LabelRepo::list_for_issue(&pool, issue_id)
        .await
        .unwrap()
        .into_iter()
        .map(|l| l.id)
        .collect();
    assert_eq!(
        applied,
        [bug_id, high_id].into_iter().collect(),
        "priority/high must have replaced priority/low, leaving bug untouched"
    );

    // Commented on.
    IssueCommentRepo::insert(
        &pool,
        edda_domain::IssueCommentId::new(),
        issue_id,
        alice,
        "investigating now",
    )
    .await
    .unwrap();
    let comments = IssueCommentRepo::list_for_issue(&pool, issue_id)
        .await
        .unwrap();
    assert_eq!(comments.len(), 1);
    assert_eq!(comments[0].body, "investigating now");

    // Closed.
    let closed_state = IssueState::Closed {
        closed_at: 1_700_000_000,
        reason: CloseReason::Completed,
    };
    IssueRepo::update_state(&pool, issue_id, &closed_state)
        .await
        .unwrap();
    let issue = IssueRepo::find_by_repository_and_number(&pool, repository.id, number)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(issue.state, closed_state);
}

#[tokio::test]
async fn a_branch_protection_rule_round_trips_and_can_be_deleted() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let repository = repo(alice, "demo", Visibility::Public);
    RepositoryRepo::insert(&pool, &repository).await.unwrap();

    let rule_id = edda_domain::BranchProtectionRuleId::new();
    BranchProtectionRepo::insert(&pool, rule_id, repository.id, "main", 2)
        .await
        .unwrap();

    let found = BranchProtectionRepo::find_for_branch(&pool, repository.id, "main")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.required_approvals, 2);
    assert!(
        BranchProtectionRepo::find_for_branch(&pool, repository.id, "develop")
            .await
            .unwrap()
            .is_none()
    );

    let rules = BranchProtectionRepo::list_for_repository(&pool, repository.id)
        .await
        .unwrap();
    assert_eq!(rules.len(), 1);

    assert!(BranchProtectionRepo::delete(&pool, repository.id, rule_id)
        .await
        .unwrap());
    assert!(
        BranchProtectionRepo::find_for_branch(&pool, repository.id, "main")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_team_grant_and_a_direct_grant_both_contribute_to_the_effective_role() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let bob = insert_user(&pool, "bob").await;

    let owners_team_id = OrganizationRepo::insert(
        &pool,
        edda_domain::OrganizationId::new(),
        "acme",
        None,
        alice,
    )
    .await
    .unwrap();

    let repository = repo(alice, "widgets", Visibility::Private);
    RepositoryRepo::insert(&pool, &repository).await.unwrap();
    RepoAccessRepo::grant_owner(&pool, repository.id, AccessSubject::User(alice))
        .await
        .unwrap();

    // Bob has no direct grant on this repository at all.
    assert!(
        RepoAccessRepo::find(&pool, repository.id, AccessSubject::User(bob))
            .await
            .unwrap()
            .is_none()
    );

    // Bob is a member of the org's Owners team, but that team has no
    // grant on this particular repository — no effective access yet.
    assert!(TeamMemberRepo::is_member(&pool, owners_team_id, alice)
        .await
        .unwrap());
    TeamMemberRepo::add(&pool, owners_team_id, bob)
        .await
        .unwrap();
    let team_roles = RepoAccessRepo::team_roles_for_user(&pool, repository.id, bob)
        .await
        .unwrap();
    assert!(team_roles.is_empty());

    // Attaching the Owners team to the repository with Write grants every
    // member — including bob, who has no direct grant — effective write
    // access.
    RepoAccessRepo::grant(
        &pool,
        repository.id,
        AccessSubject::Team(owners_team_id),
        RepoRole::Write,
    )
    .await
    .unwrap();
    let team_roles = RepoAccessRepo::team_roles_for_user(&pool, repository.id, bob)
        .await
        .unwrap();
    assert_eq!(team_roles, vec![RepoRole::Write]);
    let direct = RepoAccessRepo::find(&pool, repository.id, AccessSubject::User(bob))
        .await
        .unwrap()
        .map(|access| access.role);
    assert_eq!(
        effective_repo_role(direct, &team_roles),
        Some(RepoRole::Write)
    );

    // A subsequent direct Admin grant to bob wins over the team's Write.
    RepoAccessRepo::grant(
        &pool,
        repository.id,
        AccessSubject::User(bob),
        RepoRole::Admin,
    )
    .await
    .unwrap();
    let direct = RepoAccessRepo::find(&pool, repository.id, AccessSubject::User(bob))
        .await
        .unwrap()
        .map(|access| access.role);
    assert_eq!(
        effective_repo_role(direct, &team_roles),
        Some(RepoRole::Admin)
    );
}

#[tokio::test]
async fn an_organizations_owners_team_is_named_and_permissioned_as_expected() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let owners_team_id = OrganizationRepo::insert(
        &pool,
        edda_domain::OrganizationId::new(),
        "acme",
        Some("Acme Corp"),
        alice,
    )
    .await
    .unwrap();

    let team = TeamRepo::find_by_id(&pool, owners_team_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(team.name, "Owners");
    assert_eq!(team.permission, TeamPermission::Admin);
}

#[tokio::test]
async fn a_repository_created_under_an_organization_grants_its_owners_team_ownership() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let org = edda_domain::OrganizationId::new();
    let owners_team_id = OrganizationRepo::insert(&pool, org, "acme", None, alice)
        .await
        .unwrap();

    let repository = Repository {
        id: RepositoryId::new(),
        owner: RepositoryOwner::Organization(org),
        name: "widgets".to_string(),
        description: None,
        visibility: Visibility::Public,
        forked_from: None,
    };
    RepositoryRepo::insert_with_owner_team(&pool, &repository, owners_team_id)
        .await
        .unwrap();

    let access = RepoAccessRepo::find(&pool, repository.id, AccessSubject::Team(owners_team_id))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(access.role, RepoRole::Owner);
}

#[tokio::test]
async fn a_team_unit_permission_override_replaces_the_teams_default_for_that_unit_only() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let org = edda_domain::OrganizationId::new();
    OrganizationRepo::insert(&pool, org, "acme", None, alice)
        .await
        .unwrap();

    TeamRepo::insert(
        &pool,
        edda_domain::TeamId::new(),
        org,
        "developers",
        TeamPermission::Read,
    )
    .await
    .unwrap();
    let team = TeamRepo::find_by_org_and_name(&pool, org, "developers")
        .await
        .unwrap()
        .unwrap();

    assert!(
        TeamRepo::find_unit_permission(&pool, team.id, TeamUnit::Code)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(team.code_role(None), Some(RepoRole::Read));

    TeamRepo::set_unit_permission(&pool, team.id, TeamUnit::Code, TeamPermission::Write)
        .await
        .unwrap();
    let overridden = TeamRepo::find_unit_permission(&pool, team.id, TeamUnit::Code)
        .await
        .unwrap();
    assert_eq!(overridden, Some(TeamPermission::Write));
    assert_eq!(team.code_role(overridden), Some(RepoRole::Write));

    // Setting it again (not inserting a second row) replaces, not adds.
    TeamRepo::set_unit_permission(&pool, team.id, TeamUnit::Code, TeamPermission::Admin)
        .await
        .unwrap();
    assert_eq!(
        TeamRepo::find_unit_permission(&pool, team.id, TeamUnit::Code)
            .await
            .unwrap(),
        Some(TeamPermission::Admin)
    );
}

#[tokio::test]
async fn team_membership_can_be_added_and_removed() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    let bob = insert_user(&pool, "bob").await;
    let org = edda_domain::OrganizationId::new();
    OrganizationRepo::insert(&pool, org, "acme", None, alice)
        .await
        .unwrap();
    TeamRepo::insert(
        &pool,
        edda_domain::TeamId::new(),
        org,
        "developers",
        TeamPermission::Write,
    )
    .await
    .unwrap();
    let team = TeamRepo::find_by_org_and_name(&pool, org, "developers")
        .await
        .unwrap()
        .unwrap();

    assert!(!TeamMemberRepo::is_member(&pool, team.id, bob)
        .await
        .unwrap());
    TeamMemberRepo::add(&pool, team.id, bob).await.unwrap();
    assert!(TeamMemberRepo::is_member(&pool, team.id, bob)
        .await
        .unwrap());
    let members = TeamMemberRepo::list_members(&pool, team.id).await.unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].id, bob);

    let removed = TeamMemberRepo::remove(&pool, team.id, bob).await.unwrap();
    assert!(removed);
    assert!(!TeamMemberRepo::is_member(&pool, team.id, bob)
        .await
        .unwrap());
}

#[tokio::test]
async fn organization_names_are_unique_case_insensitively() {
    let pool = crate::test_pool().await;
    let alice = insert_user(&pool, "alice").await;
    OrganizationRepo::insert(
        &pool,
        edda_domain::OrganizationId::new(),
        "acme",
        None,
        alice,
    )
    .await
    .unwrap();
    let err = OrganizationRepo::insert(
        &pool,
        edda_domain::OrganizationId::new(),
        "ACME",
        None,
        alice,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        crate::organization_repo::InsertOrganizationError::NameTaken
    ));
}
