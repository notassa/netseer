> **Status (2026-11-18): reviewed, partly adopted.** Adopted: I1 counted once (option a: I1 stays in incident impact, roll-up unweighted), k^1.5 relabelled as a NetSeer heuristic, health framed as a triage index. Not adopted: weighted-mean roll-up (not monotonic), EMA intensity, lookback window. Deferred: ATT&CK-breadth signal. See CONCEPTS A5.4 "Redesign review".

# NetSeer Risk Redesign — Grounded Build Brief

**For:** a Claude coding agent redesigning NetSeer's incident risk scoring + network health.
**Goal of this file:** give the agent *only verified ground truth* + *decided direction* + *hard anti-hallucination rules*, so it redesigns without inventing formulas, weights, or citations.

---

## 0. HARD RULES (read first, obey always)

1. **No invented formulas, weights, or thresholds.** Every number you add must come from §3 (current, verified from code) or §5 (external, cited). If a value is not in this file, you do not have it — ask the owner.
2. **Do not fabricate citations.** Use only the sources in §5/§7. Never cite a paper, repo, or doc not listed here. If you need a formula that §6 marks "source-only / not captured," STOP and read the named primary source before coding.
3. **A number is either verified or flagged.** Anything in §6 (UNVERIFIED) must not be presented as fact or hard-coded as if proven.
4. **Follow NetSeer's own process (CLAUDE.md).** Risk constants, schema, feature list, and the CONCEPTS A5 model are owner-controlled. You MUST propose edits to `docs/CONCEPTS.md` first and get the owner's go-ahead **before** changing scoring code. Do not change a test's expected value to make it pass.
5. **This is a redesign, not a rewrite.** Keep the architecture: FastAPI + SQLite (WAL), pure-Python deterministic scorer, local LLM explains only (never scores), single box, no new services, no ML in scoring.
6. **Every claim in your own output needs evidence:** a `file:line`, a test result, or a §5 citation. If unverified, say "unknown."

---

## 1. System facts (fixed constraints)

- NetSeer = local Suricata-based IDS alert interpretation + prioritisation for **small flat networks**.
- Stack: FastAPI + Uvicorn, SQLite (WAL), Jinja2 + HTMX + Chart.js, Ollama (explanation only). No ML in scoring.
- Scoring code lives in: `netseer/src/engine/scorer.py`, `netseer/src/engine/constants.py`, `netseer/src/engine/acp.py`, `netseer/src/engine/ti.py`.
- Model spec of record: `docs/CONCEPTS.md` §A5 (CONCEPTS wins over any other doc).
- Tests: `pytest netseer/tests`; `test_scorer.py` currently asserts the CONCEPTS A5.6 worked example (**health = 62**). Changing the roll-up math changes this number — see §8.

---

## 2. The three loopholes (what is being fixed)

| # | Loophole | Where in code |
|---|---|---|
| **L1** | Roll-up uses a rank-damped noisy-OR `D(x)=1−Πₖ(1−x₍ₖ₎/k^1.5)`; the `k^1.5` exponent has **no primary source**, and the union **saturates** (splitting one incident into two inflates risk). | `scorer.damped_union`, `constants.DAMPING_P=1.5` |
| **L2** | **Asset criticality (I1) is counted twice** at network level: once inside each incident's impact `I` (via `A=(I1+I2)/2`), then again as the roll-up weight `I1/9`. | `scorer.impact` + `scorer.network_health` / `roll_up` |
| **L3** | **Alert volume → risk** via `L2 = min(9, 3·log10(1+n))`, and **Network Health = 100·(1−joint probability)** is an unvalidated index. | `scorer.l2`, `scorer.health` |

---

## 3. CURRENT MODEL — verified ground truth (from code; preserve unless §4 changes it)

Source: `scorer.py` + `constants.py`, read 2026-11-19. These are facts, not proposals.

**Likelihood** `L = mean(present factors L1..L5)`, each 0–9:
- `L1` = ET `signature_severity` {Critical:9, Major:7, Minor:4, Informational:1} overrides Suricata `priority` {1:9,2:6,3:3,4:1}; exception: Informational yields to priority.
- `L2` = `min(9, 3*log10(1+n_alerts))`.
- `L3` = rule strength {single:2, R1:6, R2:5, R3:7, R4:9}.
- `L4` = direction {ext→int:9, int→ext:7, int→int:6, ext→ext:1}.
- `L5` = `max(abuseipdb/100, min(1, vt_malicious/5))*9`; counted **only if it raises L**.

**Impact** `I = I3*(0.5 + 0.5*A/9)`, `A=(I1+I2)/2`:
- `I1` device-type criticality {server:9, network:8, workstation:6, phone:5, iot:5, guest:3, unknown:5}.
- `I2` port sensitivity {21,22,23,139,445,1433,3306,3389,5432,5900:9; 80,443,8080,8443:6; else:4}.
- `I3` classtype impact {trojan-activity/command-and-control/successful-admin/successful-user:9 … not-suspicious:1; unknown:4}.

**Band & score**
- Level cuts `(3.0, 6.0)` → Low/Medium/High per axis.
- OWASP 3×3 matrix → Note/Low/Medium/High/Critical.
- `R = 10*(L/9)*(I/9)`  (0–10).

**Decay & roll-up**
- `pᵢ = R/10 * 0.5**(age_seconds / (half_life_days*86400))`  (exponential half-life).
- `D(x sorted desc) = 1 − Πₖ(1 − x₍ₖ₎ / k**1.5)`  (`DAMPING_P=1.5`).
- Device risk `P(d) = D(pᵢ over incidents involving d)`.
- Network health `P(N) = D((I1ᵢ/9)*pᵢ over non-Note incidents)`; `health = round(100*(1−P(N)))`.

**Correlation (keep — see §4)**: R1 same attacker→victim diff sigs; R2 one src→≥5 dst (sweep); R3 ≥5 src→one dst (brute/DoS); R4 MITRE tactic progression. `SWEEP_MIN_HOSTS=5`, `FAN_IN_MIN_SOURCES=5`.

**Keep unchanged (already standards-grounded):** the OWASP Likelihood×Impact matrix, the L1/L3/L4/I3 factor maps, correlation R1–R4, dedup (alert_groups→incident_groups). Justification: OWASP Risk Rating + NIST SP 800-30 (§5). Do **not** redesign these.

---

## 4. DECIDED REDESIGN DIRECTION (per loophole)

Each fix states: the change, the citation, and whether it is an **owner decision** (present options, do not pick silently) or a **default to implement**.

### Fix L1 — replace the `k^1.5` noisy-OR roll-up
- **Delete** `DAMPING_P=1.5` and the noisy-OR union as the network/device aggregator. It has no source and saturates. (Evidence: Lei et al. CloudCom 2024 rejected an OR union "because it saturates": {0.1,0.1,0.99}→OR 0.991 vs {0.99,0.99,0.99}→OR 0.999, indistinguishable; arithmetic mean gives 0.397 vs 0.99 — §5.)
- **Default to implement:** a **criticality-weighted mean** of the decayed incident probabilities for the roll-up (bounded 0–1, non-saturating, transparent). This also carries the asset weight for Fix L2.
- **Owner decision (present, don't pick alone):** if the owner wants to keep a union shape, the only cited alternative is a **semantically-gated OR** (Longueira-Romero 2022: gate each input by context factors so "many lows don't make a critical"), or **log-odds/logit pooling** (general method, bounded). Recommend the mean; list these as alternatives.
- **Forbidden:** reintroducing any rank exponent (`k^p`) — no source exists for it.

### Fix L2 — count asset criticality exactly once
- **Rule (unanimous across all frameworks in §5):** asset value enters in exactly one place.
- **Default to implement:** **remove I1 from per-incident impact** (change `I` so impact is asset-free — e.g. drive impact from `I2`,`I3` only) and apply asset criticality **once** as the roll-up weight. Template: Elastic applies criticality as a separate category *after* aggregation; Rapid7 uses a single multiplier tier set.
- **Owner decision:** the two valid homes are (a) criticality **inside** incident impact + **unweighted** roll-up, or (b) criticality **out** of impact + weighted roll-up (recommended, pairs with Fix L1). Pick one, never both. Owner confirms which.
- **Weights:** keep NetSeer's existing device-type→value map (§3 `I1`) as the criticality source; if converting to a multiplier, Elastic's {0.5,1,1.5,2} and Rapid7's {0.5,0.75,1,1.5,2} tiers are the citable precedents for the *shape* (§5). Do not invent new tier numbers.

### Fix L3 — volume + health index
- **Volume:** keep volume as a **dampened** signal (the existing `log` already curbs inflation) but prefer **temporal intensity** over a static count. Cited option: EMA intensity `λ(t)=α·N(t)+(1−α)·λ(t−1)`, `α=0.3` (Gurjar & Camp 2026). **Caveat (must honor):** that paper's final scorer is ML and uncalibrated, and its headline metrics are internally inconsistent — adopt the *feature idea only*, not any number.
- **Breadth-as-risk (recommended add):** reward distinct MITRE ATT&CK tactics on one host instead of raw count (Splunk default rule: ≥3 distinct tactics / ≥4 sources / 7 days). NetSeer already tracks MITRE tactics for R4 — reuse that.
- **Decay:** honest finding — leading products use a **fixed sliding lookback window**, not an exponential decay term (Elastic 30-day; Splunk 24h/7d). **Owner decision:** keep the current exponential half-life (defensible, simpler) *or* switch to a documented lookback window (more industry-aligned). If a decay curve is kept, OpenCTI decay rules are the citable precedent. Do not silently switch.
- **Health index:** keep a single 0–100 Network Health number **only** as a reproducible, **decomposable** triage index (always drill down to contributing incidents/devices), never claimed as a calibrated probability of compromise (ISACA standardized-scoring guidance).

---

## 5. VERIFIED EXTERNAL SOURCES (cite these, nothing else)

| Tag | Source | Use | What is verified |
|---|---|---|---|
| STANDARD | OWASP Risk Rating Methodology — owasp.org/www-community/OWASP_Risk_Rating_Methodology | Justify current matrix (keep) | Risk=Likelihood×Impact; factors 0–9; levels 0–<3 Low / 3–<6 Med / 6–9 High; 3×3 matrix |
| STANDARD | NIST SP 800-30 Rev.1 — nvlpubs.nist.gov | Justify matrix + asset-once | Risk = likelihood × impact via risk-level matrix; asset value in impact axis |
| PEER | Lei, Madi, Nitschke, Zhao, Pourzandi, "Multi-target Risk Score Aggregation," IEEE CloudCom 2024 — people.scs.carleton.ca/~lianyingzhao/cloudcom2024-ming-authorscopy.pdf | Fix L1 (reject union, use mean) | OR union saturates (0.991 vs 0.999); mean preserves (0.397 vs 0.99); deterministic, no ML |
| PEER+OSS | Longueira-Romero et al., "Gotta Catch 'em All: Aggregating CVSS," RECSI 2022 / arXiv:2310.02062; code `aaalongueira/CVSS_Aggregation` | Fix L1 alt (gated OR) | Gate inputs by λ=ρ·β·γ·μ so many lows ≠ critical. Validated on 1 case only |
| PEER | Gurjar & Camp, "Predicting Tail-Risk Escalation in IDS Alert Time Series," arXiv:2601.14299 (16 Jan 2026) | Fix L3 (volume as EMA intensity) | 251M Suricata alerts; EMA λ(t)=αN+(1−α)λ, α=0.3. CAVEAT: final scorer ML/uncalibrated; metrics inconsistent |
| PRODUCT | Elastic entity risk scoring — elastic.co/guide/en/security (v8.18) | Fix L1 template + Fix L2 (criticality once) | Criticality weights {Low0.5,Med1,High1.5,Extreme2} applied AFTER aggregation; bands <20/20–40/40–70/70–90/>90; worked ex 36.16+16.95=53.11; 30-day window |
| PRODUCT | Splunk ES Risk-Based Alerting — help.splunk.com (ES 7.3, 2025) | Fix L1 + L3 breadth | Additive risk per object; default rule ≥3 MITRE tactics / ≥4 sources / 7d, or sum>100/24h |
| PRODUCT | Rapid7 InsightVM criticality — docs.rapid7.com/insightvm/adjusting-risk-with-criticality | Fix L2 (single multiplier) | Tiers {VeryLow0.5,Low0.75,Med1,High1.5,VeryHigh2}; per-vuln score cannot take the modifier |
| STANDARD | CVSS v4.0 Environmental (CR/IR/AR), FIRST spec v1.2 (released 1 Nov 2023) — first.org/cvss/v4-0 | Fix L2 + "severity≠risk" | Asset importance folded once into impact; CVSS must NOT be a direct IDS incident score |
| COMMUNITY+OSS | SSVC — cisa.gov/ssvc; PyPI `ssvc` v1.2.3 (2025-08-29, Apache/MIT) | Fix L1+L2 together (optional bigger refactor) | Deterministic decision tree; asset enters once as Mission & Well-being; embeddable Python |
| OSS | `ait-aecid/aecid-alert-aggregation` (GPL-3.0, pushed 2024-03-19) | Reference for alert→incident grouping | Time-window grouping + attack-phase tag + similarity merge. METHOD reuse only (GPL) |
| OSS | OpenCTI decay rules — docs.opencti.io/latest/administration/decay-rules | Fix L3 decay precedent (if kept) | lifetime + decay factor + reaction points + revoke score. Exact curve is source-only |
| COMMUNITY | EPSS v4 (FIRST, live Mar 2025) — first.org/epss | Optional per-signature prior | Daily exploit probability 0–1 for a CVE; cite only, do not treat as incident risk |
| PRACTITIONER | ISACA "Standardized Scoring for Security and Risk Metrics" (2017) | Fix L3 health framing | A 0–100 index must be reproducible, transparent, decomposable |

---

## 6. UNVERIFIED / DO NOT FABRICATE (explicit holes)

Treat each as "unknown." Do not hard-code or cite as fact.
- **No primary source exists for a `k^1.5` / Riemann-zeta rank-damping of security scores.** It is an unbacked heuristic → remove it; do not re-derive or defend it.
- **Elastic's exact aggregation formula / zeta constant** is NOT in public docs (engineering-blog/source only). Cite Elastic's *behaviour*, never a closed-form equation.
- **OpenCTI / MISP exact decay polynomial** and **aecid/scas/RITA scoring math** live only in source. Read the source before porting; do not reconstruct from memory.
- **NetSeer's `I2` port-sensitivity scale and the `k^1.5` exponent** have no external backing — keep `I2` only as a labelled custom heuristic, or demote it.
- **Gurjar & Camp numbers** (accuracy %) are inconsistent in the paper — use the EMA feature idea only, never a metric.
- Verification caveat: GitHub API was blocked during research; repo dates came from web pages. Re-confirm a repo's latest commit before depending on it.

---

## 7. Source classification (for the FYP writeup)

- **Formal standards:** OWASP Risk Rating, NIST SP 800-30, CVSS v4.0.
- **Peer-reviewed:** Lei 2024 (CloudCom), Longueira-Romero 2022 (RECSI/arXiv), Gurjar & Camp 2026 (arXiv).
- **Product implementations:** Elastic, Splunk ES RBA, Rapid7, Microsoft Exposure Mgmt.
- **Open-source:** SSVC lib, aecid-alert-aggregation, OpenCTI, EPSS clients, Wazuh.
- **NetSeer custom (label as such):** `I2` port scale, impact shape `I3·(0.5+0.5·A/9)`, the specific R1–R4 thresholds, the health index formula.

---

## 8. Implementation workflow (do these in order)

1. **Propose CONCEPTS.md edits first.** Draft the A5 changes for Fixes L1–L3 (new roll-up = weighted mean; criticality once; volume/decay decision; health-as-triage-index). Present the §4 owner decisions. **Get owner go-ahead before touching scoring code.** (CLAUDE.md: don't change risk constants/model on your own.)
2. **Recompute the A5.6 worked example.** The roll-up change makes the old `health = 62` wrong. Compute the new expected value by hand from the new model, put it in CONCEPTS A5.6, and only then update `test_scorer.py`'s expected number. Never edit the test to pass without the owner-approved recomputed value.
3. **Edit `constants.py`:** remove `DAMPING_P`; add any new, owner-approved constants (criticality-multiplier tiers if chosen, EMA `α`, lookback window if chosen). No invented numbers.
4. **Edit `scorer.py`:** replace `damped_union`-based roll-up with the weighted-mean roll-up; remove I1 from `impact` (if option b chosen); add EMA intensity and/or ATT&CK-breadth to volume handling per owner decision; keep decomposability (network_health must still return contributing incidents/devices).
5. **Keep untouched:** OWASP matrix, L1/L3/L4/I3 maps, correlation R1–R4, dedup, TI module.
6. **Test:** `pytest netseer/tests`. All must pass with owner-approved expected values. Add regression tests for the new roll-up (e.g. "splitting one incident into two does not raise network risk" — the anti-saturation property from Lei 2024).
7. **Document:** update `docs/CONCEPTS.md`, `docs/WRITEUP.md` (explanation + §8 numbers), `docs/progress.md` (one line), with citations from §5.

**Done means:** owner-approved CONCEPTS change + code matching it + green tests with recomputed expected values + each new constant traceable to §5. If any value can't be traced, stop and ask.