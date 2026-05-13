# Change Log

## v1.3.10
    * `docs/security/supply-chain.md` §7 gains §7.1 "Development environment posture" — names the controls operating on the cathedral / maintainer-laptop release environment: workstation controls (FileVault, automatic screen lock, automatic OS updates, password manager with maximum-entropy random passwords), identity controls (hardware-bound passkey MFA on every release-signing identity, `OpenSecOps-Org` organisation-wide MFA enforcement, branch protection on `main` re-verified weekly by OpenSSF Scorecard), what the cathedral model removes from the threat surface (no long-lived signing keys, no CI release path, no external committers), and what is logged for audit (Sigstore Rekor public transparency log, GitHub organisation audit log, Scorecard SARIF). Closes with a "future expansion contingent on client requirement" paragraph stating CI/CD-anchored controls (SLSA Build L2 in particular, plus any S2C2F or SSDF item presuming a hosted build platform) will be considered if a specific enterprise customer requires them. ToC and §13 intake-checklist crosswalk updated.

## v1.3.9
    * `docs/security/supply-chain.md` §1: rewrote the converted-set listing to name all 24 OpenSecOps components alphabetically, and replaced the Python-only conversion-artefact list with a two-shape description (Python-bearing components carry `requirements.in`/`requirements.txt`/SBOM/provenance; libraryless components emit a deterministic `git archive HEAD` source tarball plus a SLSA Build L1 in-toto provenance document, all Sigstore-signed identically). Reflects the steady-state where every component publishes through the same `./publish` toolchain.

## v1.3.8
    * Releases of this repository are now Sigstore-signed. Each GitHub Release ships four assets: the `git archive HEAD` source tarball, a SLSA Build L1 in-toto provenance document attesting to it, and Sigstore `.bundle` signatures for each. Customers downloading the docs can verify the bytes against the OpenSecOps signing identity using the recipe in `docs/security/supply-chain.md` §9.3.

## v1.3.7
    * Enable auto-close workflow for external pull requests, enforcing the cathedral governance policy uniformly across all OpenSecOps repositories. Pull requests from non-team authors are closed automatically with a redirect comment pointing to the bug-report template, the GitHub Security Advisory flow, and the fork-under-MPL-2.0 path.
    * `docs/security/supply-chain.md` §1: add a cross-link to the [Trust page](https://www.opensecops.org/trust.html) alongside the existing intake-checklist pointer, positioning the Trust page as the lighter customer-facing synthesis and this document as the canonical reference.

## v1.3.6
    * `docs/security/supply-chain.md` §1: converted-set listing updated from "SOAR and Installer" to the full current set (Installer, SOAR, Foundation-control-tower-log-aggregator, Foundation-default-vpc-remover, Foundation-infra-immutable-tagger, Foundation-instance-port-report, Foundation-limit-log-group-retention, SOAR-all-alarms-to-sec-hub, SOAR-detect-log-buckets, SOAR-detect-stack-drift, SOAR-SAM-Automating-Forensic-Disk-Collection, SOAR-soc-incident-when-s3-tag-applied). §14 glossary entry for "Converted component" reworded to point at §1 rather than naming the set inline, so future conversions only require the §1 update.

## v1.3.5
    * `docs/security/supply-chain.md` §5.5 + §13 crosswalk: OpenSSF Scorecard bullet and intake row updated to reflect that publication to scorecard.dev is currently suppressed (`publish_results: false` in `scorecard.yml`) as a workaround for a Sigstore TUF rotation that the `ossf/scorecard-action` bundled `trusted_root.json` cannot chain forward through; per-check findings remain visible via SARIF upload to GitHub Code Scanning. Re-enabling dashboard publication is a one-line edit pending a refreshed action release. The longer treatment notes that Scorecard in practice is consumed primarily as a signal that one *has* a Scorecard rather than as a source of metrics any reviewer reads, and points reviewers at §5.1–§5.4, §6, and §9 as the substantive supply-chain assurance set.

## v1.3.4
    * `docs/security/supply-chain.md` §5 gains §5.6 "Runtime-bundled dependencies" — documents the deliberate asymmetry between `boto3` (explicitly hash-pinned across all components, currently `boto3==1.42.94`, overrides the Lambda-runtime-bundled version) and `cfnresponse` (stays runtime-managed, unpinned). Reasoning is captured per dependency: boto3 has broad attack surface and runtime-version drift; cfnresponse has trivial scope, AWS-runtime-canonical trust root, and convention preservation. ToC updated.

## v1.3.3
    * `docs/security/supply-chain.md` §5.5 gains the live poll-based daily-scan layer + Scorecard externally-verifiable signals; §13 crosswalk gains a Scorecard row.

## v1.3.2
    * `docs/security/supply-chain.md`: §6 gains a SLSA Build L1 in-toto provenance asset; §8 splits into S2C2F + SLSA subsections; §9 gains Sigstore signature verification (§9.3) and lock reproducibility (§9.4) recipes; §13 crosswalk gains rows for SLSA L1, signed artefacts, and lock reproducibility.

## v1.3.1
    * `docs/security/supply-chain.md` §5 gains §5.5 "Continuous detection between releases" — push-based GitHub Dependabot alerts are now enabled on every OpenSecOps repository in alerts-only mode (no auto-PRs), with no SLA on detection-to-notification latency and customer-side cross-check options (`pip-audit` or OSV.dev queries against the published locks). §13 intake-checklist crosswalk gains a continuous-detection row; the existing dependency-bot row is rewritten to reference §5.5's alerts-only framing so the two rows are mutually consistent.

## v1.3.0
    * Added docs/security/supply-chain.md — authoritative cross-component customer-facing page covering supply-chain integrity, CVE response, SBOM artefacts, release verification, and an intake-checklist crosswalk for FOSS-intake reviewers, security officers, and engineers.

## v1.2.0
    * Reworked chapter 7 (Authentication and Authorisation). Minor edits otherwise.

## v1.1.2
    * Updated screen shots, links to OpenSecOps on GitHub, and corrected a few typos.

## v1.1.1
    * Further adjustments and removal of obsolete information.

## v1.1.0
    * Removed obsolete information.

## v1.0.2
    * Fixed documentation links to use OpenSecOps-Org instead of CloudSecOps-Org.

## v1.0.1
    * Created comprehensive README.md for the Documentation repository.

## v1.0.0
    * Initial release.
