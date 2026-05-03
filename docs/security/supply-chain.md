# OpenSecOps Supply-Chain Security and CVE Response

This document is the authoritative customer-facing reference for the OpenSecOps platform's supply-chain posture, CVE-response process, and release-verification artefacts. Each component repository's `SECURITY.md` links here for the full picture; `SECURITY.md` is the single canonical per-component policy file (there is no separate `GOVERNANCE.md`), and this document is the cross-component complement.

It is written to serve two readerships at once:

- **Security and FOSS-intake reviewers, AppSec officers, CISOs, procurement reviewers** evaluating "is this software safe to bring into our enterprise?" Each section leads with the property the reviewer cares about and anchors it to a named industry framework ([S2C2F](https://github.com/ossf/s2c2f), [CycloneDX](https://cyclonedx.org/), [CISA SSDF](https://www.cisa.gov/resources-tools/resources/secure-software-development-attestation-form), CRA, MPL-2.0) or to a verification artefact the reviewer can pull and inspect.
- **Engineers installing or operating OpenSecOps** who need the concrete mechanics — the exact files in the source tree, the exact commands to verify a release, the exact recipe to determine whether a deployment is exposed to a specific CVE.

OpenSecOps is published source-available under [MPL-2.0](https://www.mozilla.org/en-US/MPL/2.0/). The cathedral governance model (transparent source, no external pull requests; vulnerability reports welcomed and credited) applies uniformly to every component.

## Table of contents

- [1. About OpenSecOps and the scope of this document](#1-about-opensecops-and-the-scope-of-this-document)
- [2. Supported versions and the release model](#2-supported-versions-and-the-release-model)
- [3. Vulnerability disclosure](#3-vulnerability-disclosure)
- [4. CVE response SLA](#4-cve-response-sla)
- [5. Supply-chain integrity](#5-supply-chain-integrity)
  - [5.1 Hash-verified dependency resolution](#51-hash-verified-dependency-resolution)
  - [5.2 Malicious-package gating](#52-malicious-package-gating)
  - [5.3 Direct-dependency provenance](#53-direct-dependency-provenance)
  - [5.4 Release-time gate](#54-release-time-gate)
- [6. Software Bill of Materials (SBOM)](#6-software-bill-of-materials-sbom)
  - [6.1 Aggregate component-level SBOM](#61-aggregate-component-level-sbom)
  - [6.2 Per-function evidence tarball](#62-per-function-evidence-tarball)
- [7. Governance and contribution model](#7-governance-and-contribution-model)
- [8. Maturity claims (S2C2F)](#8-maturity-claims-s2c2f)
- [9. Verifying a release](#9-verifying-a-release)
  - [9.1 Hash verification of a deployed dependency set](#91-hash-verification-of-a-deployed-dependency-set)
  - [9.2 Reproducing the per-function SBOM and provenance](#92-reproducing-the-per-function-sbom-and-provenance)
- [10. "Am I affected by CVE-XXXX?" recipe](#10-am-i-affected-by-cve-xxxx-recipe)
- [11. Acknowledged-and-deferred CVEs](#11-acknowledged-and-deferred-cves)
- [12. Subscribing to security advisories](#12-subscribing-to-security-advisories)
- [13. Intake-checklist crosswalk](#13-intake-checklist-crosswalk)
- [14. Glossary](#14-glossary)

---

## 1. About OpenSecOps and the scope of this document

OpenSecOps is enterprise security-automation software for AWS environments, with admin-equivalent privilege scope in customer accounts (notably the SOAR component, which orchestrates Security Hub findings, runs auto-remediations, and creates incident tickets). The blast radius of a compromised release is therefore comparable to the blast radius of a compromised CSPM, EDR, or SIEM, and OpenSecOps is built and released with that bar in mind.

The supply-chain posture described in §5–§9 applies to every OpenSecOps component that has been **converted** to the platform's hash-pinned dependency model. Conversion means the component carries:

- hand-edited `requirements.in` files declaring direct dependencies for each Lambda function,
- machine-generated, hash-verified `requirements.txt` lock files (one per Lambda function),
- a per-component `.security-config.toml` carrying the per-component values,
- a generated `SECURITY.md` rendered from the project-wide template plus the per-component config,
- per-function CycloneDX SBOMs (`requirements.cdx.json`) and PyPI publisher-provenance baselines (`requirements.provenance.json`) committed alongside each `requirements.in`.

At the time of writing, **SOAR** and **Installer** are converted. Other OpenSecOps components (`Foundation-*`, `AFT`, the `SOAR-*` satellites) are governed by the same project-wide policies — governance, vulnerability disclosure, CVE-response SLA, MPL-2.0 licensing — and are progressively brought onto the same supply-chain artefact set; every component that has converted is held to the same uniform posture, with no per-component variation and no quiet exemptions.

**Release authority** for every published artefact across every OpenSecOps component is held by the OpenSecOps core team. There is no external committer pool, no automated release path, and no auto-merge dependency bots — see §7.

Reviewers working from a procurement or FOSS-intake checklist may want to skip ahead to §13 for a question-by-question crosswalk; the sections leading up to it carry the framing and warrants the crosswalk's "by design" answers depend on.

## 2. Supported versions and the release model

OpenSecOps follows a **moving-release-line** model: security fixes ship as **new releases**, never as patches against prior versions. There is no backport policy. A customer running an older release receives a fix by upgrading to the current release.

This is honest about scale: a small core team cannot sustainably maintain multiple parallel release lines per component, and parallel release lines compound the supply-chain attack surface (more lock files to keep current, more SBOMs to publish per CVE event, more independent regression-test runs). The single-moving-release model is uniform across every OpenSecOps component, is documented in each component's `SECURITY.md` §1, and is acknowledged here at intake to avoid surprise.

A reviewer concerned about "what if we cannot upgrade immediately when a CVE drops?" should consult §4 (the SLA windows for fix-bearing releases) and §10 (the recipe for determining whether an existing deployment is actually exposed to a given CVE). The remediation when exposed is to upgrade to the current release.

## 3. Vulnerability disclosure

Vulnerability reports are welcomed from anyone. Reporters receive **named credit** in the release notes for the version that ships the fix, unless they request anonymity.

**Preferred channel**: the GitHub Security Advisory ("Report a vulnerability") flow on the affected component repository under the [OpenSecOps-Org GitHub organization](https://github.com/OpenSecOps-Org). This produces a private advisory visible only to the core team. The public Issues tab is for non-security defects only — a public issue mentioning an unpatched vulnerability is itself a disclosure event.

The **reporter / contributor distinction** is intentional and structural. The cathedral governance model (§7) closes the contribution path entirely — external pull requests are not accepted on any OpenSecOps repository, for any change. Vulnerability *reports* are the explicit carve-out: anyone can tell us something is broken; the fix itself is authored by the core team. This separation is what allows OpenSecOps to publish a coordinated disclosure on a known timeline without coordinating with anonymous external committers.

This dual posture (open reports, closed contributions) is documented in each component's `SECURITY.md` §2 and §6.

## 4. CVE response SLA

When a CVE is confirmed against a currently-supported release of a converted component, a fix-bearing release ships within these windows:

| Severity     | Time to next release          |
| ------------ | ----------------------------- |
| Critical     | within **3 business days**    |
| High         | within **10 business days**   |
| Medium / Low | next regular release          |

Critical and high severities trigger an **out-of-band** release; medium and low ride the regular release cadence. The clock starts when the core team accepts the report as a confirmed vulnerability against current code.

This SLA is **uniform across every converted OpenSecOps component**. It is documented in each component's `SECURITY.md` §3.

**Severity authority** for SLA classification: GHSA severity is authoritative when present; otherwise NVD or OSV CVSS severity. Findings without classification are treated as **high** until manually re-classified, so absence of a severity label cannot be used to slow-walk a fix.

The release-time gate (§5.4) is independent of severity: it fails on **any** `pip-audit` finding regardless of severity, unless that finding is on the per-component acknowledged-and-deferred list (§11). The SLA above governs *release timing*; the gate governs *what is allowed to ship*.

## 5. Supply-chain integrity

Every converted OpenSecOps component carries four mutually reinforcing integrity properties: hash-verified dependency resolution, malicious-package gating, direct-dependency PyPI provenance, and a release-time gate that re-verifies all three before any artefact ships. Each is described below in terms of the property a security reviewer cares about, followed by the mechanism an engineer can verify.

### 5.1 Hash-verified dependency resolution

**Property**: a compromised package registry — PyPI itself, a mirror, or a proxy on the install path — cannot silently substitute malicious code into an OpenSecOps deployment. Tampered bytes are rejected at install time.

**Mechanism**: every Lambda function's resolved dependency set (every direct and transitive dependency, exact version) is recorded in a `requirements.txt` lock file with a SHA-256 hash for each artefact. Locks are generated on the maintainer machine by `uv pip compile --generate-hashes` from a hand-edited abstract-spec file (`requirements.in`). At customer install time, `pip` (invoked by `sam build`) refuses to install any package whose downloaded bytes do not match the recorded hash — pip enforces this automatically when every entry in a `requirements.txt` carries hashes.

The lock files are the canonical evidence: they are committed to git, ship with every release tag, and can be inspected directly. See §9.1 for the customer-runnable verification command.

This addresses the hash-verified-resolution control in S2C2F **L1** (component pinning) and **L2** (lock files with cryptographic verification at install time).

### 5.2 Malicious-package gating

**Property**: known-malicious packages from typosquat, dependency-confusion, and account-takeover attacks cannot be present in any released OpenSecOps lock.

**Mechanism**: the release-time gate (§5.4) cross-references every pinned package against the [OSSF malicious-packages feed](https://github.com/ossf/malicious-packages) — the public, community-maintained catalog of confirmed malicious package versions. A match fails the release with the matching `MAL-*` advisory ID. The feed is fetched current at release time (its commit SHA is recorded for audit); it is threat-intelligence data and is never frozen.

This addresses the locally-runnable subset of S2C2F **L3** (malicious-package detection at build time).

### 5.3 Direct-dependency provenance

**Property**: drift in the publisher attribution of any direct dependency is surfaced for maintainer review before a release ships. This is an early-warning signal for upstream account compromise, maintainer transitions, or namespace takeovers.

**Mechanism**: for each Lambda function, the release tooling captures PyPI's published metadata for every direct dependency (the abstract `requirements.in` declarations plus any transitively-included `-r` references) — uploader/maintainer set, verified-publisher attribute, project-URL set — into a committed `requirements.provenance.json` file. The release gate re-fetches the same metadata at gate time and warns when any field has drifted from the committed baseline. The maintainer reviews drift the same way they review lock-file diffs.

This is **advisory** rather than a hard gate because PyPI's JSON metadata reflects upload-time values supplied by the uploader — "verified" project URLs prove URL control at verification time, not a continuing publisher relationship — and is not a hard authentication signal on its own. Where [PyPI Trusted Publishers](https://docs.pypi.org/trusted-publishers/) or [PEP 740 attestations](https://peps.python.org/pep-0740/) are available for a specific dependency, those can be promoted from advisory to hard gate per-dependency. Absent those, the advisory captures the signal honestly without overclaiming.

This addresses the locally-runnable subset of S2C2F **L3** (direct-dependency provenance verification).

### 5.4 Release-time gate

**Property**: nothing reaches a customer without first passing every integrity check above. The release tooling refuses to publish if any check fails.

**Mechanism**: the maintainer's `./publish` script runs `_check-requirements.sh` as its first step. The gate performs five independent checks, each able to fail the release on its own:

1. **Lock-source drift** — recompiles each `requirements.in` and compares to the committed `requirements.txt`; fails on any difference. Catches the case where the maintainer edited a `.in` but forgot to recompile.
2. **CVE scan** — runs [`pip-audit`](https://pypi.org/project/pip-audit/) against every committed lock; fails on any finding except those listed on the acknowledged-and-deferred list (§11).
3. **Hash integrity** — re-downloads each pinned artefact from PyPI and verifies its SHA-256 matches the recorded hash. This is the same verification `pip` performs at customer `sam build` time, run at the gate so byte-level tampering is caught **before** the deploy reaches a customer.
4. **Malicious-package check** — cross-references every pinned package against the OSSF feed (§5.2); fails on any match.
5. **Provenance check** — re-checks PyPI publisher metadata against the committed provenance baselines (§5.3); warns on drift.

All five checks fire independently; failure of one does not skip the others, so a release-blocking diagnostic is always complete. The gate runs entirely on the maintainer's machine — there is no release-path CI and no automated update bots. CI presence elsewhere in the project is detection-only and read-only.

## 6. Software Bill of Materials (SBOM)

Every release of a converted OpenSecOps component on the public OpenSecOps remote ships **two SBOM-related assets** attached to the GitHub release. The aggregate is a [CycloneDX 1.6](https://cyclonedx.org/specification/overview/) document; the evidence tarball is a deterministic archive containing CycloneDX 1.6 per-function documents and their provenance baselines.

### 6.1 Aggregate component-level SBOM

`<COMPONENT>-<VERSION>-sbom.cdx.json` — one [CycloneDX 1.6](https://cyclonedx.org/specification/overview/) document, uncompressed JSON, the union of every per-function SBOM in the release. This is what most SBOM-consuming tooling and most intake reviewers operate on.

The aggregate carries canonical CycloneDX fields:

- `metadata.tools` records the SBOM generators used (cyclonedx-py and uv) with versions, so a reviewer can reproduce the generation conditions.
- `metadata.lifecycles` records the build phase per [CycloneDX lifecycle vocabulary](https://cyclonedx.org/docs/1.6/json/#metadata_lifecycles).
- Per-component `hashes[]` carry the canonical SHA-256 for each artefact (hoisted from the underlying lock files; not hidden inside `externalReferences[]`).
- `bom-ref` identifiers are derived from package URLs ([purl](https://github.com/package-url/purl-spec)) for stable cross-document referencing.

Asset URL pattern (replace `<COMPONENT>` with the component name and `<VERSION>` with the release tag):

```
https://github.com/OpenSecOps-Org/<COMPONENT>/releases/download/<VERSION>/<COMPONENT>-<VERSION>-sbom.cdx.json
```

**Union semantics for duplicate components** — the aggregate may legitimately list the same package at multiple versions across different Lambda functions. Each function resolves its own dependency graph independently from its own `requirements.in`, so transitive resolutions can differ across functions. Collapsing duplicates to "highest wins" would actively misrepresent what is deployed, so the aggregate preserves every distinct version present in any function's resolved lock. The per-function SBOMs in the evidence tarball (§6.2) carry the function-by-function attribution.

### 6.2 Per-function evidence tarball

`<COMPONENT>-<VERSION>-evidence.tar.gz` — a deterministic gzip tarball containing every `requirements.cdx.json` and `requirements.provenance.json` in the source tree, one set per Lambda function. This is the deep-audit witness set: per-function CycloneDX SBOMs plus the corresponding PyPI publisher-provenance baselines.

The tarball is **byte-deterministic**: arcnames are anchored at the repo root, file metadata (`mtime`, `uid`, `gid`, ownership) is zeroed, entries are sorted, and gzip is invoked with `mtime=0`. Re-bundling the same source tree produces a byte-identical tarball; this is what makes the evidence usable as evidence rather than as a convenience archive.

Asset URL pattern:

```
https://github.com/OpenSecOps-Org/<COMPONENT>/releases/download/<VERSION>/<COMPONENT>-<VERSION>-evidence.tar.gz
```

The per-function evidence files are also visible directly in the source tree at the canonical paths `**/requirements.cdx.json` and `**/requirements.provenance.json` next to each `requirements.in`. A reviewer who clones the repo at a specific release tag can verify the published evidence tarball against the source-tree files at that tag — the bundle is byte-deterministic and the source files are directly comparable.

**Choosing between the two assets**: a reviewer needing only an inventory of components and versions stops at the aggregate (§6.1). A reviewer performing CycloneDX-mature deep audit (per-function attribution, publisher-provenance crosswalk) pulls the evidence tarball.

## 7. Governance and contribution model

OpenSecOps follows the [cathedral model in Eric S. Raymond's sense](https://en.wikipedia.org/wiki/The_Cathedral_and_the_Bazaar): a small core team curates the codebase. The source is public for transparency, customer verification, and security review. It is **not** an invitation to contribute code.

- **External pull requests are not accepted** on any OpenSecOps repository, for any change. Forks under MPL-2.0 are of course permitted by the licence.
- **Vulnerability reports are the explicit carve-out** (§3): reports are welcomed from anyone; reporters receive named credit; the fix itself is authored by the core team.
- **Release authority** for every published artefact is held by the OpenSecOps core team. There is no automated release path and no auto-merge dependency bot.

The cathedral framing, the no-external-PR policy, and the vulnerability-disclosure channel are documented uniformly in each component's `SECURITY.md` §2 and §6. There is no separate `GOVERNANCE.md` — `SECURITY.md` is the single canonical home for governance and supply-chain posture together, because intake reviewers open one file, not two, and procurement questionnaires ask about both in the same breath.

The reason this matters for supply-chain reviewers specifically: the closed-contribution model means there is no path by which an external committer can land code in an OpenSecOps release without going through the named core team. The "could a hostile contributor sneak something in?" question is closed by design rather than by review process.

## 8. Maturity claims (S2C2F)

Each converted OpenSecOps component implements **[S2C2F](https://github.com/ossf/s2c2f) Level 1 + Level 2 baseline plus the locally-runnable subset of Level 3**:

- **L1 + L2 baseline**: hand-edited abstract dependency spec; hash-verified resolved lock; release-time CVE scan; explicit acknowledged-and-deferred override (§11); deterministic regeneration of the lock from the same `.in` files plus the same `uv` version.
- **L3 subset**: OSSF malicious-packages feed gating at release time (§5.2); direct-dependency PyPI provenance advisory at release time (§5.3). Both gates fire uniformly against every converted component — the same checks applied to the same artefacts in the same way, with no per-component carve-outs.

**Out of scope and explicitly not claimed**:

- Any S2C2F L3 control that requires write-capable CI infrastructure (signed-from-CI rebuilds, auto-merge on green dependency bumps).
- Any S2C2F L4 control (rebuilding OSS on trusted infrastructure, signing rebuilt OSS, implementing upstream fixes locally).

These exclusions are by design: release authority remains on the maintainer machine, there is no release-path CI, and there is no internal rebuild infrastructure for upstream OSS. Pursuing them would require operational changes that this project has deliberately not made.

The maturity claim is **uniform across every converted OpenSecOps component**. It is documented in each component's `SECURITY.md` §8.

## 9. Verifying a release

Two independent verifications are available to any customer or reviewer with no maintainer cooperation, against any published OpenSecOps release tag.

### 9.1 Hash verification of a deployed dependency set

The `requirements.txt` files committed in the source tree (and present unchanged inside `.aws-sam/build/` after `sam build`) carry SHA-256 hashes for every pinned artefact. To re-download from PyPI and verify the bytes match the recorded hashes:

```bash
# In a fresh shell, with `pip` available:
cd <component-repo>/functions/<function-name>/
pip download --require-hashes --no-deps \
    -r requirements.txt -d /tmp/verify-out
```

Exit 0 means every artefact downloaded from PyPI matches at least one recorded SHA-256 hash. A non-zero exit (with pip's canonical `THESE PACKAGES DO NOT MATCH THE HASHES` error) indicates either tampering on the path PyPI → you, or a stale/edited lock; in either case the customer's `sam build` would also reject the install. This command is the same hash check pip performs on install, run on demand against an unmodified release tag.

### 9.2 Reproducing the per-function SBOM and provenance

The per-function `requirements.cdx.json` and `requirements.provenance.json` files in the evidence tarball (and in the source tree) are byte-deterministic given the same lock and the same generator versions. To regenerate them and compare:

```bash
# From the root of a converted component repo, at a specific release tag:
cd <component-repo>/
./compile-requirements
# `requirements.cdx.json` and `requirements.provenance.json` next to each
# `requirements.in` are regenerated. Compare against the committed copies:
git diff --stat
```

`./compile-requirements` is a top-level entry point in every converted component repository; it is a thin symlink to the canonical script in the project's `Installer` repository, distributed identically to every component by the maintainer's refresh tooling so the regeneration logic is the same script everywhere. A clean `git diff` after re-running it is the verification: the committed evidence files match what the public tooling produces from the committed locks.

The aggregate component-level SBOM (§6.1) is regenerated at release time from the per-function SBOMs; once §9.1 and §9.2 are clean, the aggregate is a deterministic union of files the reviewer has already verified.

## 10. "Am I affected by CVE-XXXX?" recipe

To determine whether a specific CVE applies to a deployment of any converted OpenSecOps component, run the following against the deployed `requirements.txt` files inside the SAM build artefacts:

```bash
grep -rE '<package>==<vulnerable-version-pattern>' path/to/.aws-sam/build/
```

Worked example — checking exposure to a hypothetical urllib3 CVE that affects all versions before 2.6.3:

```bash
grep -rE '^urllib3==(0\.|1\.|2\.[0-5]\.|2\.6\.[0-2])' .aws-sam/build/
```

A non-empty result means at least one Lambda function bundle contains the vulnerable version. Cross-reference §11 to determine whether the exposure is a release-gate failure that escaped (file a bug via the GitHub Security Advisory flow — §3) or an acknowledged-and-deferred entry (consult the resolution date). Per §2, the remediation when exposed is to upgrade to the current release.

If the deployment is built but not yet deployed, the `.aws-sam/build/` directory under the component's source root carries the same `requirements.txt` files that customers run against. If the deployment is already in production and the build artefacts are no longer locally available, the same recipe runs against the source tree at the deployed release tag (the `requirements.txt` files in source are bit-identical to the ones inside `.aws-sam/build/`, because `sam build` copies them in unchanged before installing).

## 11. Acknowledged-and-deferred CVEs

The release-time gate (§5.4) fails on any `pip-audit` finding by default. Each component's `SECURITY.md` §12 carries an **acknowledged-and-deferred CVE list**: the explicit, per-component override mechanism that lets a known finding ship if (and only if) the maintainer has reviewed it and recorded the rationale.

Each entry, when present, contains: CVE ID, affected package, date acknowledged, reason (development-only dependency, contested advisory, fix pending upstream, no exploitable code path, etc.), and expected resolution date.

Adding an entry is a **deliberate maintainer action**, reviewed at release time, and the entry is removed as soon as the underlying issue is fixed; the audit trail remains in `git log`. The list is not a way to ignore findings; it is a way to ship transparently in the cases where shipping with an acknowledged finding is the more defensible action than withholding the release.

A reviewer can determine, for any release of any converted component, exactly which findings (if any) were knowingly accepted in that release by reading §12 of the component's `SECURITY.md` at that tag.

## 12. Subscribing to security advisories

Three channels reach customers when an OpenSecOps security release ships:

- **GitHub Security Advisories on the affected component repository**. Each repo in the [OpenSecOps-Org organization](https://github.com/OpenSecOps-Org) publishes advisories via GitHub's native Security tab. To receive notifications, watch the repo with "Custom → Security alerts" enabled in GitHub's notification settings.
- **GitHub Releases on the affected component repository**. Every fix-bearing release is published with release notes that name the CVE(s) addressed and credit the reporter (per §3). Watch the repo with "Custom → Releases" enabled.
- **The component's `SECURITY.md` §12**. The acknowledged-and-deferred CVE list is updated as state changes; consult it as part of any deployment review.

A customer who wants the lightest-touch subscription can watch each deployed component repository with "Releases" only — every security release is a release, and the release notes name the CVEs.

## 13. Intake-checklist crosswalk

For reviewers working from a standard FOSS-intake or procurement questionnaire, the table below maps the typical questions to where the answer lives in this document and (where applicable) in the per-component `SECURITY.md`.

| Intake question                                            | Answer / location                                                              |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------ |
| Is there a published vulnerability disclosure policy?      | Yes — §3 and per-component `SECURITY.md` §2                                    |
| Is there a CVE-response SLA?                               | Yes — §4 (3 / 10 business days for critical / high; uniform across components) |
| Is there a CycloneDX or SPDX SBOM per release?             | Yes — CycloneDX 1.6, two assets per release: aggregate + evidence tarball (§6) |
| Are dependencies pinned by hash?                           | Yes — every direct and transitive dependency, SHA-256 (§5.1)                   |
| Is there a release-time CVE scan that gates publication?   | Yes — `pip-audit` against every committed lock; fail-closed (§5.4)             |
| Is there a malicious-package check at release time?        | Yes — OSSF malicious-packages feed cross-reference (§5.2)                      |
| Is there direct-dependency provenance verification?        | Yes — committed PyPI publisher-provenance baselines, advisory drift check (§5.3) |
| What S2C2F level is claimed?                               | L1 + L2 baseline + locally-runnable subset of L3, uniform per converted component (§8) |
| Are external pull requests accepted?                       | No — cathedral model (§7); vulnerability *reports* are the explicit carve-out  |
| Is there a backport policy for older releases?             | No — fixes ship as new releases (§2)                                           |
| What licence?                                              | [MPL-2.0](https://www.mozilla.org/en-US/MPL/2.0/) across every component       |
| Can a customer independently verify a release?             | Yes — hash verification (§9.1) and per-function SBOM determinism (§9.2)        |
| How does a customer know whether they are exposed to a CVE? | The grep recipe in §10, run against the deployed `requirements.txt` files     |
| Where are acknowledged-but-not-yet-fixed CVEs documented?  | Per-component `SECURITY.md` §12 (§11 of this document explains the mechanism)  |
| Is there an automated update path / dependency bot?        | No, by design — updates are deliberate maintainer actions under the cathedral governance model (§7, §5.4) |

For any intake question not covered above, the appropriate channel is the GitHub Security Advisory flow on the relevant component repository (§3) — including questions where the reviewer wants confirmation that an answer above applies to a specific release tag.

## 14. Glossary

- **`.in` file (`requirements.in`)** — hand-edited abstract dependency spec for a single Lambda function; lists direct dependencies with version ranges. The "intent" file. See §5.1.
- **`.txt` file (`requirements.txt`)** — machine-generated lock file derived from a `.in` file by `uv pip compile --generate-hashes`. Contains every direct *and* transitive dependency pinned to an exact version with a SHA-256 hash. The "resolved value" file, read by `pip` at customer install time. See §5.1.
- **`.security-config.toml`** — per-component configuration consumed by the `SECURITY.md` generator. Carries the per-component values (component name, supported versions, SBOM URL pattern, acknowledged-and-deferred CVE list).
- **Aggregate SBOM** — single CycloneDX 1.6 document, the union of every per-function SBOM in a release; the `<COMPONENT>-<VERSION>-sbom.cdx.json` GitHub Release asset. See §6.1.
- **Cathedral model** — closed-contribution governance posture (no external pull requests; vulnerability reports welcomed and credited); per [Raymond, *The Cathedral and the Bazaar*](https://en.wikipedia.org/wiki/The_Cathedral_and_the_Bazaar). See §7.
- **Converted component** — an OpenSecOps component repository that carries the full hash-pinned dependency artefact set (§1). At time of writing: SOAR and Installer.
- **CycloneDX** — [OWASP-stewarded SBOM specification](https://cyclonedx.org/) used by OpenSecOps for both per-function and aggregate SBOMs. Version 1.6.
- **Evidence tarball** — deterministic gzip archive of every `requirements.cdx.json` and `requirements.provenance.json` in a release; the `<COMPONENT>-<VERSION>-evidence.tar.gz` GitHub Release asset. See §6.2.
- **Lambda function** — an AWS Lambda function packaged by SAM. OpenSecOps components are SAM applications composed of many Lambda functions; each function has its own `requirements.in` / `requirements.txt` / SBOM / provenance baseline.
- **MPL-2.0** — [Mozilla Public License 2.0](https://www.mozilla.org/en-US/MPL/2.0/), the licence under which every OpenSecOps component is published.
- **OSSF malicious-packages feed** — [community-maintained catalog](https://github.com/ossf/malicious-packages) of confirmed malicious package versions (typosquats, dependency-confusion attacks, account-takeover-published versions). Cross-referenced at release-gate time. See §5.2.
- **`pip-audit`** — [PyPA-maintained](https://pypi.org/project/pip-audit/) CVE scanner for `requirements.txt` files. Run by the release-time gate against every committed lock. See §5.4.
- **PyPI** — [Python Package Index](https://pypi.org/), the canonical Python package registry.
- **Release-time gate** — `_check-requirements.sh`, the integrity gate `./publish` runs as its first step. Five independent checks: lock-source drift, CVE scan, hash integrity, malicious-package check, provenance check. See §5.4.
- **S2C2F** — [Secure Supply Chain Consumption Framework](https://github.com/ossf/s2c2f) (OSSF). The framework against which OpenSecOps's maturity claim is anchored. See §8.
- **SAM** — [AWS Serverless Application Model](https://aws.amazon.com/serverless/sam/). The build and deploy framework OpenSecOps components use; `sam build` is what installs the pinned, hashed dependencies for each Lambda function.
- **`uv`** — [Astral's Rust-based Python package manager](https://docs.astral.sh/uv/). Used **only** as the lock-file compiler on the maintainer machine, never at customer install time. See §5.1.
