# Change Log

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
