# Persistent Store and a Config File — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the pod an on-disk RDF store (`--rdf-store rocksdb:<dir>`) and a TOML config file, with precedence flag > env > file > default.

**Architecture:** The signatures already exist as a compiling skeleton with `todo!()` bodies (commits `537f51f`, `eeff431`). Every task fills bodies. Precedence is not implemented: file values are installed as clap defaults, and clap's own flag > env > default resolution produces the rest.

**Tech Stack:** Rust, clap 4.6 (derive + env), oxigraph 0.5.9 (`rocksdb` feature, on by default), serde 1 (derive), toml 0.9.

## Global Constraints

- **The signatures in the skeleton are given.** Tasks fill bodies only. No new public functions, no new modules. The one exception is Task 6, which changes `blame_file`'s third parameter — spelled out there.
- **No hand-written precedence.** `value_source` must not appear in `src/config.rs`. Pinned by `docs/constraints.md`, "Precedence is clap's, never hand-written".
- **No config search path.** No literal config filename in `src/`. Pinned by `docs/constraints.md`, "The config file is never found, only named".
- **`toml` stays pinned to `0.9`** — `rudof_lib` already pulls in 0.9.12, and 1.x would put two majors of a TOML parser in one binary.
- **Every command runs inside the nix dev shell:** `nix develop --command <cmd>`. Outside it `openssl-sys` fails to build.
- **`arch-check` must exit 0** after every task. Run it before each commit.
- Spec: `docs/superpowers/specs/2026-07-31-cli-config-design.md`. Record: root spec §16 ADR-7.

---

### Task 1: The on-disk store

**Files:**
- Modify: `src/store.rs` — `OxigraphStore::open`
- Modify: `src/config.rs` — `Config::rdf_store`
- Test: `src/store.rs` (`mod tests`), `src/config.rs` (`mod tests`)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `OxigraphStore::open(dir: &std::path::Path) -> Result<OxigraphStore, StoreError>`; `Config::rdf_store(&self) -> Result<std::sync::Arc<dyn SparqlStore>, String>`.

- [ ] **Step 1: Write the failing persistence test**

Append to `src/store.rs`'s `mod tests`:

```rust
    // The property the flag exists for. A test that only asserts `open`
    // returns `Ok` passes against a backend that persists nothing.
    #[tokio::test]
    async fn rocksdb_backend_survives_a_reopen() {
        let dir = std::env::temp_dir()
            .join(format!("sparql-pod-store-{}", uuid::Uuid::new_v4()));
        {
            let store = OxigraphStore::open(&dir).expect("open");
            store
                .update("INSERT DATA { GRAPH <urn:t> { <urn:s> <urn:p> <urn:o> } }")
                .await
                .expect("write");
            // Dropped here: RocksDB's exclusive lock is released by the drop,
            // and the reopen below is what proves the bytes outlived it.
        }
        let reopened = OxigraphStore::open(&dir).expect("reopen");
        assert!(reopened
            .ask("ASK { GRAPH <urn:t> { <urn:s> <urn:p> <urn:o> } }")
            .await
            .expect("read"));
        drop(reopened);
        std::fs::remove_dir_all(&dir).ok();
    }
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `nix develop --command cargo test --lib rocksdb_backend_survives_a_reopen`
Expected: FAIL, panicking at `not yet implemented: 2026-07-31-cli-config-design.md §3`

- [ ] **Step 3: Implement `OxigraphStore::open`**

Replace the `todo!()` body in `src/store.rs`:

```rust
    pub fn open(dir: &std::path::Path) -> Result<Self, StoreError> {
        Store::open(dir)
            .map(|inner| Self { inner })
            .map_err(|e| StoreError::Backend(e.to_string()))
    }
```

- [ ] **Step 4: Run it to make sure it passes**

Run: `nix develop --command cargo test --lib rocksdb_backend_survives_a_reopen`
Expected: PASS

- [ ] **Step 5: Write the failing backend-selection test**

Append to `src/config.rs`'s `mod tests`:

```rust
    // Mirrors `blob_store_selects_a_backend_and_refuses_an_unknown_one`. The
    // rejected `http://…` pins the unimplemented remote backend as a refusal
    // rather than leaving it to be assumed.
    #[test]
    fn rdf_store_selects_a_backend_and_refuses_an_unknown_one() {
        let mut cfg =
            Config::parse_from(["sparql-pod", "--owner-webid", "https://a.example/#me"]);
        assert_eq!(cfg.rdf_store, "memory", "the default is the in-memory store");
        assert!(cfg.rdf_store().is_ok());

        let dir = std::env::temp_dir()
            .join(format!("sparql-pod-cfg-store-{}", uuid::Uuid::new_v4()));
        cfg.rdf_store = format!("rocksdb:{}", dir.display());
        assert!(cfg.rdf_store().is_ok());
        std::fs::remove_dir_all(&dir).ok();

        cfg.rdf_store = "http://oxigraph:7878/".into();
        assert!(cfg.rdf_store().is_err(), "an unimplemented backend must refuse to start");
        cfg.rdf_store = "nonsense".into();
        assert!(cfg.rdf_store().is_err());
    }
```

- [ ] **Step 6: Run it to make sure it fails**

Run: `nix develop --command cargo test --lib rdf_store_selects_a_backend`
Expected: FAIL, panicking at `not yet implemented: 2026-07-31-cli-config-design.md §3`

- [ ] **Step 7: Implement `Config::rdf_store`**

Replace the `todo!()` body in `src/config.rs`:

```rust
    pub fn rdf_store(&self) -> Result<std::sync::Arc<dyn crate::store::SparqlStore>, String> {
        let spec = self.rdf_store.trim();
        if spec == "memory" {
            return crate::store::OxigraphStore::in_memory()
                .map(|s| std::sync::Arc::new(s) as std::sync::Arc<dyn crate::store::SparqlStore>)
                .map_err(|e| format!("--rdf-store memory: {e}"));
        }
        if let Some(dir) = spec.strip_prefix("rocksdb:") {
            return crate::store::OxigraphStore::open(std::path::Path::new(dir))
                .map(|s| std::sync::Arc::new(s) as std::sync::Arc<dyn crate::store::SparqlStore>)
                .map_err(|e| format!("--rdf-store rocksdb: {e}"));
        }
        Err(format!(
            "--rdf-store: expected `memory` or `rocksdb:<dir>`, got `{spec}`"
        ))
    }
```

- [ ] **Step 8: Run the whole suite and the constraints**

Run: `nix develop --command cargo test && arch-check`
Expected: all tests pass; `arch-check` exits 0 and prints nothing

- [ ] **Step 9: Commit**

```bash
git add src/store.rs src/config.rs
git commit -m "feat(store): hold the RDF store on disk with --rdf-store rocksdb:<dir>"
```

---

### Task 2: Read the config file

**Files:**
- Modify: `src/config.rs` — `FileConfig::read`
- Test: `src/config.rs` (`mod tests`)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `FileConfig::read(path: &std::path::Path) -> Result<FileConfig, clap::Error>`.

- [ ] **Step 1: Write the failing tests**

Append to `src/config.rs`'s `mod tests`:

```rust
    fn write_temp_toml(body: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir()
            .join(format!("sparql-pod-{}.toml", uuid::Uuid::new_v4()));
        std::fs::write(&p, body).expect("write temp toml");
        p
    }

    #[test]
    fn a_file_supplies_what_it_names_and_leaves_the_rest_unset() {
        let p = write_temp_toml("owner_webid = \"https://a.example/#me\"\nmax_body_bytes = 42\n");
        let f = FileConfig::read(&p).expect("reads");
        assert_eq!(f.owner_webid.as_deref(), Some("https://a.example/#me"));
        assert_eq!(f.max_body_bytes, Some(42));
        assert_eq!(f.listen, None);
        std::fs::remove_file(&p).ok();
    }

    // §4.1: a key this binary does not know is a typo, and a pod that starts
    // with less configuration than was written looks exactly like one
    // configured correctly.
    #[test]
    fn an_unknown_key_refuses_the_start() {
        let p = write_temp_toml("owner_web_id = \"https://a.example/#me\"\n");
        assert!(FileConfig::read(&p).is_err());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn malformed_toml_refuses_the_start() {
        let p = write_temp_toml("owner_webid = \n");
        assert!(FileConfig::read(&p).is_err());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn an_unreadable_path_refuses_the_start() {
        let p = std::env::temp_dir().join("sparql-pod-does-not-exist.toml");
        assert!(FileConfig::read(&p).is_err());
    }
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `nix develop --command cargo test --lib config::tests::a_file_supplies`
Expected: FAIL, panicking at `not yet implemented: 2026-07-31-cli-config-design.md §4, §4.1`

- [ ] **Step 3: Implement `FileConfig::read`**

Replace the `todo!()` body in `src/config.rs`:

```rust
    fn read(path: &std::path::Path) -> Result<Self, clap::Error> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            clap::Error::raw(
                clap::error::ErrorKind::Io,
                format!("--config {}: {e}\n", path.display()),
            )
        })?;
        toml::from_str(&text).map_err(|e| {
            clap::Error::raw(
                clap::error::ErrorKind::InvalidValue,
                format!("--config {}: {e}\n", path.display()),
            )
        })
    }
```

- [ ] **Step 4: Run them to make sure they pass**

Run: `nix develop --command cargo test --lib config::tests`
Expected: PASS, including the four new tests

- [ ] **Step 5: Commit**

```bash
arch-check
git add src/config.rs
git commit -m "feat(config): read the TOML file and refuse an unknown key"
```

---

### Task 3: Render the file as clap defaults

**Files:**
- Modify: `src/config.rs` — `FileConfig::as_defaults`
- Test: `src/config.rs` (`mod tests`)

**Interfaces:**
- Consumes: `FileConfig::read` from Task 2.
- Produces: `FileConfig::as_defaults(&self) -> std::collections::BTreeMap<&'static str, Vec<String>>`. Keys are clap **argument ids**, which under `#[derive(Parser)]` are the struct's field names — `trusted_issuers`, not the long flag `trusted-issuer`.

- [ ] **Step 1: Write the failing test**

Append to `src/config.rs`'s `mod tests`:

```rust
    // Everything is rendered to a string so the file's values travel the same
    // `value_parser` as a typed flag. The keys are argument ids, which is what
    // `Command::mut_arg` takes.
    #[test]
    fn as_defaults_renders_only_the_keys_the_file_set() {
        let p = write_temp_toml(concat!(
            "owner_webid = \"https://a.example/#me\"\n",
            "trusted_issuers = [\"https://one.example/\", \"https://two.example/\"]\n",
            "reset_root_acl = true\n",
            "max_body_bytes = 42\n",
        ));
        let d = FileConfig::read(&p).expect("reads").as_defaults();
        assert_eq!(d.get("owner_webid"), Some(&vec!["https://a.example/#me".to_string()]));
        assert_eq!(
            d.get("trusted_issuers"),
            Some(&vec!["https://one.example/".to_string(), "https://two.example/".to_string()]),
            "a list becomes several values, not one joined string"
        );
        assert_eq!(d.get("reset_root_acl"), Some(&vec!["true".to_string()]));
        assert_eq!(d.get("max_body_bytes"), Some(&vec!["42".to_string()]));
        assert_eq!(d.get("listen"), None, "an unset key must not become a default");
        std::fs::remove_file(&p).ok();
    }
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `nix develop --command cargo test --lib as_defaults_renders_only`
Expected: FAIL, panicking at `not yet implemented: 2026-07-31-cli-config-design.md §5`

- [ ] **Step 3: Implement `FileConfig::as_defaults`**

Replace the `todo!()` body in `src/config.rs`:

```rust
    fn as_defaults(&self) -> std::collections::BTreeMap<&'static str, Vec<String>> {
        let mut out = std::collections::BTreeMap::new();
        for (key, value) in [
            ("base_uri", &self.base_uri),
            ("owner_webid", &self.owner_webid),
            ("expected_audience", &self.expected_audience),
            ("listen", &self.listen),
            ("rdf_store", &self.rdf_store),
            ("blob_store", &self.blob_store),
        ] {
            if let Some(v) = value {
                out.insert(key, vec![v.clone()]);
            }
        }
        if let Some(v) = &self.trusted_issuers {
            out.insert("trusted_issuers", v.clone());
        }
        if let Some(v) = &self.allow_insecure_hosts {
            out.insert("allow_insecure_hosts", v.clone());
        }
        if let Some(v) = self.reset_root_acl {
            out.insert("reset_root_acl", vec![v.to_string()]);
        }
        if let Some(v) = self.max_body_bytes {
            out.insert("max_body_bytes", vec![v.to_string()]);
        }
        out
    }
```

- [ ] **Step 4: Run it to make sure it passes**

Run: `nix develop --command cargo test --lib as_defaults_renders_only`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
arch-check
git add src/config.rs
git commit -m "feat(config): render the file's values as clap defaults"
```

---

### Task 4: Find the config path before anything else is known

**Files:**
- Modify: `src/config.rs` — `config_path_from`
- Test: `src/config.rs` (`mod tests`)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `config_path_from<I, T>(argv: I) -> Option<std::path::PathBuf>` where `I: IntoIterator<Item = T>, T: Into<std::ffi::OsString> + Clone`.

- [ ] **Step 1: Write the failing test**

Append to `src/config.rs`'s `mod tests`:

```rust
    // The pre-parser runs before anything is known, so it must survive an argv
    // it cannot fully understand — here a required flag it has never heard of.
    // That is the case `ignore_errors` exists for, and the one most likely to
    // break silently.
    #[test]
    fn the_pre_parser_finds_config_beside_arguments_it_does_not_know() {
        let found = config_path_from([
            "sparql-pod",
            "--owner-webid",
            "https://a.example/#me",
            "--config",
            "/tmp/pod.toml",
            "--trusted-issuer",
            "https://idp.example/",
        ]);
        assert_eq!(found, Some(std::path::PathBuf::from("/tmp/pod.toml")));
    }

    #[test]
    fn the_pre_parser_returns_none_without_config() {
        let found = config_path_from(["sparql-pod", "--owner-webid", "https://a.example/#me"]);
        assert_eq!(found, None);
    }
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `nix develop --command cargo test --lib the_pre_parser`
Expected: FAIL, panicking at `not yet implemented: 2026-07-31-cli-config-design.md §5 step 1`

- [ ] **Step 3: Implement `config_path_from`**

Replace the `todo!()` body in `src/config.rs`:

```rust
fn config_path_from<I, T>(argv: I) -> Option<std::path::PathBuf>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    clap::Command::new("sparql-pod")
        .ignore_errors(true)
        .disable_help_flag(true)
        .disable_version_flag(true)
        .arg(
            clap::Arg::new("config")
                .long("config")
                .env("POD_CONFIG")
                .value_parser(clap::value_parser!(std::path::PathBuf)),
        )
        .try_get_matches_from(argv)
        .ok()?
        .get_one::<std::path::PathBuf>("config")
        .cloned()
}
```

- [ ] **Step 4: Run them to make sure they pass**

Run: `nix develop --command cargo test --lib the_pre_parser`
Expected: PASS

> **If `the_pre_parser_finds_config_beside_arguments_it_does_not_know` still fails:** `ignore_errors` stopped the parse before reaching `--config`. Do not weaken the test — it encodes the real invocation. Scan the argv by hand instead: walk the iterator for `--config <value>` and `--config=<value>`, and fall back to `std::env::var_os("POD_CONFIG")`. Keep the signature and both tests unchanged, and note the reason in a comment on the function.

- [ ] **Step 5: Commit**

```bash
arch-check
git add src/config.rs
git commit -m "feat(config): find --config before the real parse"
```

---

### Task 5: Precedence

**Files:**
- Modify: `src/config.rs` — `command_with`, `Config::try_load_from`, `Config::load`
- Test: `src/config.rs` (`mod tests`)

**Interfaces:**
- Consumes: `FileConfig::read` (Task 2), `FileConfig::as_defaults` (Task 3), `config_path_from` (Task 4).
- Produces: `command_with(defaults: BTreeMap<&'static str, Vec<String>>) -> clap::Command`; `Config::load() -> Result<Config, clap::Error>`; `Config::try_load_from<I, T>(argv: I) -> Result<Config, clap::Error>` with the same bounds as `config_path_from`.

- [ ] **Step 1: Write the failing tests**

Append to `src/config.rs`'s `mod tests`:

```rust
    fn load(args: &[&str]) -> Result<Config, clap::Error> {
        Config::try_load_from(std::iter::once("sparql-pod").chain(args.iter().copied()))
    }

    #[test]
    fn a_file_value_is_used_when_nothing_overrides_it() {
        let p = write_temp_toml(concat!(
            "owner_webid = \"https://file.example/#me\"\n",
            "listen = \"127.0.0.1:9999\"\n",
        ));
        let c = load(&["--config", p.to_str().unwrap()]).expect("loads");
        assert_eq!(c.owner_webid.as_str(), "https://file.example/#me");
        assert_eq!(c.listen.to_string(), "127.0.0.1:9999");
        std::fs::remove_file(&p).ok();
    }

    // §5.2: a file value satisfies a required argument, because clap sees an
    // argument carrying a default and treats it as present.
    #[test]
    fn a_file_satisfies_the_required_owner_webid() {
        let p = write_temp_toml("owner_webid = \"https://file.example/#me\"\n");
        assert!(load(&["--config", p.to_str().unwrap()]).is_ok());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn a_flag_beats_the_file() {
        let p = write_temp_toml(concat!(
            "owner_webid = \"https://file.example/#me\"\n",
            "listen = \"127.0.0.1:9999\"\n",
        ));
        let c = load(&["--config", p.to_str().unwrap(), "--listen", "127.0.0.1:1234"])
            .expect("loads");
        assert_eq!(c.listen.to_string(), "127.0.0.1:1234");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn a_default_survives_a_file_that_says_nothing() {
        let p = write_temp_toml("owner_webid = \"https://file.example/#me\"\n");
        let c = load(&["--config", p.to_str().unwrap()]).expect("loads");
        assert_eq!(c.rdf_store, "memory");
        assert_eq!(c.max_body_bytes, 64 * 1024 * 1024);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn a_file_list_becomes_several_values() {
        let p = write_temp_toml(concat!(
            "owner_webid = \"https://file.example/#me\"\n",
            "trusted_issuers = [\"https://one.example/\", \"https://two.example/\"]\n",
        ));
        let c = load(&["--config", p.to_str().unwrap()]).expect("loads");
        assert_eq!(c.trusted_issuers.len(), 2);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn no_config_flag_loads_nothing() {
        let c = load(&["--owner-webid", "https://a.example/#me"]).expect("loads");
        assert_eq!(c.rdf_store, "memory");
        assert!(c.config.is_none());
    }
```

> **Environment precedence is not unit-tested here.** `std::env::set_var` is process-global and Rust runs tests in threads, so an env test races every other test in this module. clap's env > default ordering is the library's own, verified in `clap_builder-4.6.0/src/parser/parser.rs:68-72` (`add_env` before `add_defaults` before `validate`), and Task 7 exercises it once by hand.

- [ ] **Step 2: Run them to make sure they fail**

Run: `nix develop --command cargo test --lib config::tests::a_file_value_is_used`
Expected: FAIL, panicking at `not yet implemented: 2026-07-31-cli-config-design.md §5`

- [ ] **Step 3: Implement `command_with`**

Replace the `todo!()` body in `src/config.rs`:

```rust
fn command_with(defaults: std::collections::BTreeMap<&'static str, Vec<String>>) -> clap::Command {
    use clap::CommandFactory;
    let mut cmd = Config::command();
    for (id, values) in defaults {
        cmd = cmd.mut_arg(id, move |a| a.default_values(values));
    }
    cmd
}
```

- [ ] **Step 4: Implement `Config::try_load_from` and `Config::load`**

Replace both `todo!()` bodies in `src/config.rs`:

```rust
    pub fn load() -> Result<Self, clap::Error> {
        Self::try_load_from(std::env::args_os())
    }

    pub fn try_load_from<I, T>(argv: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        // Collected once: the pre-parse and the real parse must see the same
        // arguments, and `I` is consumed by whichever runs first.
        let argv: Vec<std::ffi::OsString> = argv.into_iter().map(Into::into).collect();
        let defaults = match config_path_from(argv.clone()) {
            Some(p) => FileConfig::read(&p)?.as_defaults(),
            None => std::collections::BTreeMap::new(),
        };
        let matches = command_with(defaults).try_get_matches_from(argv)?;
        <Self as clap::FromArgMatches>::from_arg_matches(&matches)
    }
```

- [ ] **Step 5: Run them to make sure they pass**

Run: `nix develop --command cargo test --lib config::tests`
Expected: PASS, all of the module

- [ ] **Step 6: Commit**

```bash
arch-check
git add src/config.rs
git commit -m "feat(config): resolve flag > env > file > default through clap"
```

---

### Task 6: Point a file-caused error at the file

**Files:**
- Modify: `src/config.rs` — `blame_file`, `Config::try_load_from`
- Test: `src/config.rs` (`mod tests`)

**Interfaces:**
- Consumes: everything from Task 5.
- Produces: `blame_file(err: clap::Error, path: &std::path::Path, from_file: &BTreeMap<String, &'static str>) -> clap::Error`.

**Signature change, and why.** The skeleton declared the third parameter as
`&BTreeMap<&'static str, Vec<String>>` — the same map `as_defaults` returns, keyed by
argument id. That does not work: clap names the offending argument by its **long flag**, and
two of them differ from their id (`--trusted-issuer` → `trusted_issuers`,
`--allow-insecure-host` → `allow_insecure_hosts`). Matching them would need a heuristic that
is wrong for any future irregular long. The parameter becomes an exact **long flag → TOML
key** map, built in `try_load_from` where the `Command` is in hand.

- [ ] **Step 1: Write the failing tests**

Append to `src/config.rs`'s `mod tests`:

```rust
    // §5.1: without this the operator reads `invalid value for '--listen'` and
    // goes looking at a command line that is correct.
    #[test]
    fn a_bad_file_value_names_the_file_and_the_key() {
        let p = write_temp_toml(concat!(
            "owner_webid = \"https://file.example/#me\"\n",
            "listen = \"not-a-socket-address\"\n",
        ));
        let err = load(&["--config", p.to_str().unwrap()]).expect_err("must fail");
        let msg = err.to_string();
        assert!(msg.contains(p.to_str().unwrap()), "names the file: {msg}");
        assert!(msg.contains("listen"), "names the key: {msg}");
        std::fs::remove_file(&p).ok();
    }

    // The other half of the same rule: an error about a value the file never
    // supplied must stay exactly as clap wrote it.
    #[test]
    fn a_bad_flag_value_is_left_alone() {
        let p = write_temp_toml("owner_webid = \"https://file.example/#me\"\n");
        let err = load(&["--config", p.to_str().unwrap(), "--listen", "not-a-socket-address"])
            .expect_err("must fail");
        assert!(
            !err.to_string().contains(p.to_str().unwrap()),
            "the file did not set `listen`, so it must not be blamed"
        );
        std::fs::remove_file(&p).ok();
    }

    // The irregular case the signature exists for.
    #[test]
    fn a_bad_file_value_under_an_irregular_long_is_still_blamed() {
        let p = write_temp_toml(concat!(
            "owner_webid = \"https://file.example/#me\"\n",
            "base_uri = \"not an absolute uri\"\n",
        ));
        let err = load(&["--config", p.to_str().unwrap()]).expect_err("must fail");
        assert!(err.to_string().contains("base_uri"), "{err}");
        std::fs::remove_file(&p).ok();
    }
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `nix develop --command cargo test --lib a_bad_file_value_names_the_file`
Expected: FAIL — the message names `--listen` but not the file path

- [ ] **Step 3: Change the signature and implement `blame_file`**

Replace the whole `blame_file` function in `src/config.rs`:

```rust
/// Re-point a clap error at the file that actually caused it.
///
/// A file-supplied value arrives as a default, so clap phrases its complaint in
/// terms of a flag the operator never typed. `from_file` maps each long flag
/// the file supplied to its TOML key; an error naming one of them gets the path
/// and the key prefixed, and anything else is passed through exactly as clap
/// wrote it.
///
/// Keyed by long flag rather than by argument id because that is what clap puts
/// in the error, and the two differ wherever `#[arg(long = "…")]` renames one —
/// `--trusted-issuer` carries the id `trusted_issuers`.
fn blame_file(
    err: clap::Error,
    path: &std::path::Path,
    from_file: &std::collections::BTreeMap<String, &'static str>,
) -> clap::Error {
    use clap::error::{ContextKind, ContextValue};
    let Some(ContextValue::String(arg)) = err.get(ContextKind::InvalidArg) else {
        return err;
    };
    // clap renders the argument as it appears on the command line, e.g.
    // "--listen <LISTEN>"; only the flag itself is a stable key.
    let long = arg
        .trim_start_matches("--")
        .split([' ', '=', '<'])
        .next()
        .unwrap_or_default();
    let Some(key) = from_file.get(long) else {
        return err;
    };
    clap::Error::raw(
        err.kind(),
        format!("{}: `{key}`: {err}\n", path.display()),
    )
}
```

- [ ] **Step 4: Wire it into `Config::try_load_from`**

Replace the body written in Task 5 with:

```rust
    pub fn try_load_from<I, T>(argv: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        // Collected once: the pre-parse and the real parse must see the same
        // arguments, and `I` is consumed by whichever runs first.
        let argv: Vec<std::ffi::OsString> = argv.into_iter().map(Into::into).collect();
        let Some(path) = config_path_from(argv.clone()) else {
            let matches = command_with(Default::default()).try_get_matches_from(argv)?;
            return <Self as clap::FromArgMatches>::from_arg_matches(&matches);
        };
        let defaults = FileConfig::read(&path)?.as_defaults();
        let cmd = command_with(defaults.clone());
        // Built from the command rather than guessed, so an id and its long
        // flag can never drift apart here.
        let from_file: std::collections::BTreeMap<String, &'static str> = cmd
            .get_arguments()
            .filter_map(|a| {
                let (id, _) = defaults.get_key_value(a.get_id().as_str())?;
                Some((a.get_long()?.to_string(), *id))
            })
            .collect();
        let matches = cmd
            .try_get_matches_from(argv)
            .map_err(|e| blame_file(e, &path, &from_file))?;
        <Self as clap::FromArgMatches>::from_arg_matches(&matches)
    }
```

- [ ] **Step 5: Run them to make sure they pass**

Run: `nix develop --command cargo test --lib config::tests`
Expected: PASS, all of the module

- [ ] **Step 6: Commit**

```bash
arch-check
git add src/config.rs
git commit -m "fix(config): blame the config file for the values it supplied"
```

---

### Task 7: Document it, and start the pod against a directory

**Files:**
- Modify: `docs/deployment.md`
- Modify: `docs/superpowers/specs/2026-07-31-cli-config-design.md` — §5.1's signature note

**Interfaces:**
- Consumes: everything. Nothing produces.

- [ ] **Step 1: Run the pod against a real directory and a real file**

```bash
cd "$(mktemp -d)" && cat > pod.toml <<'TOML'
owner_webid = "https://a.example/profile/card#me"
rdf_store   = "rocksdb:./store"
blob_store  = "local:./blobs"
listen      = "127.0.0.1:3999"
TOML
nix develop --command cargo run --manifest-path "$OLDPWD/Cargo.toml" -- --config pod.toml
```

Expected: `sparql-pod listening on 127.0.0.1:3999`, and a `./store` directory containing RocksDB files. Stop it with Ctrl-C, start it again, and confirm it comes up against the existing directory.

- [ ] **Step 2: Confirm a second process is refused**

With the pod still running, in another shell run the same command again.
Expected: exit 2 with `--rdf-store rocksdb: …` naming a lock failure — the single-writer bound of ADR-7, observed rather than assumed.

- [ ] **Step 3: Confirm the environment beats the file**

```bash
POD_LISTEN=127.0.0.1:3998 nix develop --command cargo run --manifest-path "$OLDPWD/Cargo.toml" -- --config pod.toml
```

Expected: `sparql-pod listening on 127.0.0.1:3998` — the file said `3999`.

- [ ] **Step 4: Add the operator documentation**

Append to `docs/deployment.md`:

````markdown
## Where the data lives

    --rdf-store memory            (default) triples in this process, gone on restart
    --rdf-store rocksdb:<dir>     triples in <dir>
    --blob-store memory           (default) non-RDF bytes in this process
    --blob-store local:<dir>      non-RDF bytes mirroring the URL tree under <dir>

A `rocksdb:` directory is held by **one process at a time** — Oxigraph takes an exclusive
lock, so a second pod aimed at the same path refuses to start. That is a bound on processes,
not on concurrency: within the running pod, requests are served in parallel as before. Root
spec §16 ADR-7 has the reasoning, including why multi-tenancy does not collide with it (§9
runs many spaces in one process, as named graphs in one store).

Back up the store directory and the blob directory together. They are one dataset: a blob is
addressed by the resource path recorded in the triples, so a store restored without its blobs
describes bytes that are not there.

## The config file

    --config <path>
    POD_CONFIG=<path>

TOML, flat, with the flag names as keys. There is **no search path** — nothing is read unless
this names it, so a pod cannot start against a file that is invisible to whoever reads the
command line. A path that is named but unreadable, is not valid TOML, or carries a key this
binary does not know refuses the start.

```toml
base_uri     = "https://pod.toph.so/"
owner_webid  = "https://toph.so/profile/card#me"
rdf_store    = "rocksdb:/var/lib/sparql-pod/store"
blob_store   = "local:/var/lib/sparql-pod/blobs"
listen       = "127.0.0.1:3000"

trusted_issuers       = ["https://idp.toph.so/"]
expected_audience     = "https://pod.toph.so/"
allow_insecure_hosts  = []
reset_root_acl        = false
max_body_bytes        = 67108864
```

**Precedence: flag > environment > file > default.** A value in the file loses to the same
value in `POD_*`, which loses to the flag. Lists are TOML arrays, which is the reason to
prefer the file for `trusted_issuers` and `allow_insecure_hosts`: the comma-separated
environment form has to be split, trimmed and filtered, and an array does not.

An error caused by a value the file supplied names the file and the key. An error about
`--rdf-store`, `--blob-store` or `--allow-insecure-host` names the flag even when the value
came from the file — those three are checked after the parse rather than inside it.
````

- [ ] **Step 5: Correct §5.1 of the spec**

In `docs/superpowers/specs/2026-07-31-cli-config-design.md`, replace the sentence
*"`clap::Error::get(ContextKind::InvalidArg)` names the argument, and the set of keys the file
supplied is known from pass 2"* with:

```markdown
`clap::Error::get(ContextKind::InvalidArg)` names the argument by its **long flag**, and pass 2
builds a long-flag → TOML-key map from the `Command` itself for the keys the file supplied. The
map is keyed by long flag rather than by argument id because the two differ wherever
`#[arg(long = "…")]` renames one — `--trusted-issuer` carries the id `trusted_issuers` — and
matching them by hand would be a heuristic that is wrong for the next irregular long.
```

- [ ] **Step 6: Full verification**

Run: `nix develop --command cargo test && nix develop --command cargo check --all-targets && arch-check`
Expected: all tests pass, no warnings about unused items in `config.rs` (every skeleton helper is now called), `arch-check` exits 0

- [ ] **Step 7: Commit**

```bash
git add docs/deployment.md docs/superpowers/specs/2026-07-31-cli-config-design.md
git commit -m "docs(deployment): document the store directory and the config file"
```

---

## Done when

- `sparql-pod --config pod.toml` starts against a `rocksdb:` directory and finds its data after a restart.
- A second pod on the same directory refuses to start.
- Flag beats environment beats file beats default, with a test per rung.
- An unknown key, an unreadable path and malformed TOML each refuse the start.
- A value the file supplied is named with the file and the key when it is wrong.
- `arch-check` exits 0, including the two rules this work added.
- No `todo!()` remains in `src/config.rs` or `src/store.rs`.
