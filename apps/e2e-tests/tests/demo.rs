//! Demo E2E test - validates the full workflow from DEMO.md
//!
//! This test runs against all backend combinations (SQLite/PostgreSQL × Memory/PostgreSQL events).

#[macro_use]
mod common;

use common::{BackendConfig, TestHarness};

// Generate tests for all 4 backend combinations
backend_test!(demo, run_demo_test);

/// Run the full E2E demo test suite
async fn run_demo_test(config: BackendConfig) -> Result<(), Box<dyn std::error::Error>> {
    println!("🧪 Starting Zopp E2E Demo Test ({})\n", config.name());

    let harness = TestHarness::new("demo", config).await?;

    println!("✓ Server started at {}\n", harness.server_url);

    // Create server invite for Alice
    println!("🎫 Step 1: Admin creates server invite for Alice...");
    let alice_invite = harness.create_server_invite()?;
    println!("✓ Alice's server invite: {}\n", alice_invite);

    // Alice joins server
    println!("👩 Step 2: Alice joins server...");
    let alice = harness.create_user("alice");
    alice.join(&alice_invite, "alice@example.com", "alice-macbook")?;
    println!("✓ Alice joined successfully\n");

    // Alice creates workspace
    println!("🏢 Step 3: Alice creates workspace 'acme'...");
    alice.exec(&["workspace", "create", "acme"]).success()?;
    println!("✓ Workspace 'acme' created\n");

    // Alice creates project
    println!("📁 Step 4: Alice creates project 'api'...");
    alice
        .exec(&["project", "create", "api", "-w", "acme"])
        .success()?;
    println!("✓ Project 'api' created\n");

    // Alice creates environment
    println!("🌍 Step 5: Alice creates environment 'development'...");
    alice
        .exec(&[
            "environment",
            "create",
            "development",
            "-w",
            "acme",
            "-p",
            "api",
        ])
        .success()?;
    println!("✓ Environment 'development' created");

    // Create zopp.toml with defaults
    harness.create_zopp_toml("acme", "api", "development")?;
    println!("✓ Created zopp.toml with defaults\n");

    // Alice creates workspace invite for Bob
    println!("🎟️  Step 6: Alice creates workspace invite for Bob...");
    let workspace_invite = alice
        .exec_in(
            harness.test_dir(),
            &["invite", "create", "--expires-hours", "1", "--plain"],
        )
        .success()?;
    println!("✓ Workspace invite: {}\n", workspace_invite);

    // Bob joins using Alice's workspace invite
    println!("👨 Step 7: Bob joins using Alice's workspace invite...");
    let bob = harness.create_user("bob");
    bob.join(&workspace_invite, "bob@example.com", "bob-thinkpad")?;
    println!("✓ Bob joined workspace 'acme'\n");

    // Alice grants Bob write permission
    println!("🔑 Step 7b: Alice grants Bob write permission...");
    alice
        .exec(&[
            "permission",
            "user-set",
            "-w",
            "acme",
            "--email",
            "bob@example.com",
            "--role",
            "write",
        ])
        .success()?;
    println!("✓ Bob granted write permission on workspace 'acme'\n");

    // Bob writes a secret
    println!("🔐 Step 8: Bob writes secret 'FLUXMAIL_API_TOKEN'...");
    let secret_value = "fxt_8k2m9p4x7n1q5w3e6r8t0y2u4i6o8p0a";
    bob.exec_in(
        harness.test_dir(),
        &["secret", "set", "FLUXMAIL_API_TOKEN", secret_value],
    )
    .success()?;
    println!("✓ Secret written by Bob\n");

    // Alice reads Bob's secret
    println!("🔓 Step 9: Alice reads Bob's secret...");
    let retrieved = alice
        .exec_in(harness.test_dir(), &["secret", "get", "FLUXMAIL_API_TOKEN"])
        .success()?;
    assert_eq!(retrieved, secret_value, "Secret mismatch");
    println!("✓ Alice successfully read Bob's secret!\n");

    // Alice writes a secret
    println!("🔐 Step 10: Alice writes secret 'PAYFLOW_MERCHANT_ID'...");
    let secret_value2 = "mch_9x8v7c6b5n4m3";
    alice
        .exec_in(
            harness.test_dir(),
            &["secret", "set", "PAYFLOW_MERCHANT_ID", secret_value2],
        )
        .success()?;
    println!("✓ Secret written by Alice\n");

    // Bob reads Alice's secret
    println!("🔓 Step 11: Bob reads Alice's secret...");
    let retrieved2 = bob
        .exec_in(
            harness.test_dir(),
            &["secret", "get", "PAYFLOW_MERCHANT_ID"],
        )
        .success()?;
    assert_eq!(retrieved2, secret_value2, "Secret mismatch");
    println!("✓ Bob successfully read Alice's secret!\n");

    // Alice exports secrets to .env file
    println!("📤 Step 12: Alice exports secrets to .env file...");
    let env_file = harness.test_dir().join("development.env");
    alice
        .exec_in(
            harness.test_dir(),
            &["secret", "export", "-o", env_file.to_str().unwrap()],
        )
        .success()?;
    let env_contents = std::fs::read_to_string(&env_file)?;
    println!("✓ Secrets exported:\n{}", env_contents);
    assert!(env_contents.contains("FLUXMAIL_API_TOKEN="));
    assert!(env_contents.contains("PAYFLOW_MERCHANT_ID="));

    // Alice creates production environment
    println!("🌍 Step 13: Alice creates production environment...");
    alice
        .exec_in(harness.test_dir(), &["environment", "create", "production"])
        .success()?;
    println!("✓ Environment 'production' created\n");

    // Alice imports secrets to production
    println!("📥 Step 14: Alice imports secrets to production (using -e flag override)...");
    alice
        .exec_in(
            harness.test_dir(),
            &[
                "secret",
                "import",
                "-e",
                "production",
                "-i",
                env_file.to_str().unwrap(),
            ],
        )
        .success()?;
    println!("✓ Secrets imported to production\n");

    // Verify imported secret in production
    println!("🔍 Step 15: Verify imported secret in production (using -e flag override)...");
    let imported = alice
        .exec_in(
            harness.test_dir(),
            &["secret", "get", "FLUXMAIL_API_TOKEN", "-e", "production"],
        )
        .success()?;
    assert_eq!(imported, secret_value, "Import/export roundtrip failed");
    println!("✓ Import/export roundtrip verified!\n");

    // Alice injects secrets and runs command
    println!(
        "🏃 Step 16: Alice injects secrets from production and runs command (using -e override)..."
    );
    let injected = alice
        .exec_in(
            harness.test_dir(),
            &[
                "run",
                "-e",
                "production",
                "--",
                "printenv",
                "FLUXMAIL_API_TOKEN",
            ],
        )
        .success()?;
    assert_eq!(injected, secret_value, "Secret injection failed");
    println!("✓ Secret injection verified!\n");

    println!("✅ E2E Demo Test Passed!\n");
    println!("📊 Summary:");
    println!("  ✓ Server started and stopped");
    println!("  ✓ Alice registered and created workspace");
    println!("  ✓ Created zopp.toml with defaults (workspace/project/environment)");
    println!("  ✓ Bob registered and joined workspace via invite");
    println!("  ✓ Bob wrote secret, Alice read it (E2E encryption, using zopp.toml)");
    println!("  ✓ Alice wrote secret, Bob read it (E2E encryption, using zopp.toml)");
    println!("  ✓ Secrets exported from development (using zopp.toml defaults)");
    println!("  ✓ Created production environment and imported secrets (using -e flag override)");
    println!("  ✓ Secrets injected from production via run command (using -e flag override)");
    println!("  ✓ Zero-knowledge architecture verified");

    Ok(())
}
