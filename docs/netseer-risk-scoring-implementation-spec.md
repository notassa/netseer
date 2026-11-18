> **Status (2026-11-18): reviewed, not adopted as the scoring model.** NetSeer keeps the OWASP/NIST model in CONCEPTS A5. Adopted from this spec: model version + data-quality flags, deterministic ordering, evaluation tasks (CONCEPTS A5.3/A5.4). Reasons: CONCEPTS A5.4 "Weighted-sum alternative reviewed".

# NetSeer Risk Scoring Model v1.0.0

**Implementation specification for Claude Code**

## Objective

Implement a deterministic, auditable risk-scoring component for NetSeer.
The scorer ranks already-detected and already-correlated incidents. It
must not perform detection, correlation, threat-intelligence lookups,
network requests, or LLM inference.

**Architecture rule:** upstream components provide correlation counts
and threat-intelligence hit results. This module only normalises inputs,
calculates the weighted score, assigns a severity band, applies
documented band-floor overrides, and returns an audit record.

## 1. Scoring model

Use a weighted sum, not multiplication:

\[ S = `\sum`{=tex}\_i w_i s_i \]

-   Each normalised factor `s_i` is in `[0, 1]`.
-   Each weight `w_i` is non-negative.
-   All weights must sum to `1.0`.
-   The score is monotonic: increasing one factor while holding the
    others constant must never decrease the score.
-   Keep the calculation deterministic and explainable.

### Factors, normalisation, and weights

  ----------------------------------------------------------------------------------------------
  Factor           Input             Normalisation                                        Weight
  ---------------- ----------------- ------------------------------------- ---------------------
  Severity         Suricata priority `1 -> 1.0`, `2 -> 0.67`, `3 -> 0.33`                   0.35
                   (`1` is most                                            
                   severe)                                                 

  Asset            Manual            `critical -> 1.0`,                                     0.25
  criticality      asset-inventory   `workstation -> 0.5`,                 
                   tier              `unknown/unmatched -> 0.2`            

  Correlation      Number of         `min(1.0, stages / 3)`                                 0.20
                   distinct attack                                         
                   stages in                                               
                   incident                                                

  Frequency        Repeat count in   `0` if count is zero; otherwise                        0.10
                   rolling window    `min(1.0, log10(1+n) / log10(101))`   

  Threat           Whether source IP hit `-> 1.0`, no hit `-> 0.0`                          0.10
  intelligence     matches                                                 
                   blocklist/feed                                          
  ----------------------------------------------------------------------------------------------

### Normalisation constraints

-   Use fixed, documented constants. Do not derive bounds from live
    traffic or recompute them per run.
-   Asset criticality must come from a manual inventory mapping such as
    IP/hostname to tier. If no entry matches, use `0.2` and set
    `unmatched_asset=true`. Never infer an asset tier.
-   Correlation is calculated upstream. If correlation has not run, pass
    `0` stages, producing a correlation factor of `0`.
-   Frequency uses a logarithmic scale to reduce rapid saturation.
    Reference values: 3 repeats `0.3004`; 10 `0.52`; 50 `0.8519`; 100
    `1.0`.
-   Threat-intelligence lookup is upstream. The scorer receives only the
    boolean hit result and must not perform the lookup itself.

## 2. Configuration

Keep weights, band thresholds, and override parameters in a
configuration file, not hard-coded in scoring logic.

Create or adapt `risk_model_v1.yaml`:

``` yaml
version: "1.0.0"

weights:
  severity: 0.35
  asset_criticality: 0.25
  correlation: 0.20
  frequency: 0.10
  threat_intel: 0.10

bands:
  critical: 0.75
  high: 0.50
  medium: 0.25

overrides:
  critical_asset_severity_floor: 0.67
  correlation_stage_floor: 3
  floor_band: "High"
```

At configuration load time, validate that: - Every required weight
exists and is valid. - Weights are non-negative. -
`abs(sum(weights) - 1.0) < 1e-9`. - Thresholds and override values are
valid.

Fail loudly on invalid configuration. Do not silently continue with a
non-normalised weight vector.

## 3. Score and band calculation

Calculate:

\[ S = 0.35s\_{sev} + 0.25s\_{asset} + 0.20s\_{corr} + 0.10s\_{freq} +
0.10s\_{ti} \]

1.  Multiply each normalised factor by its configured weight.
2.  Sum the contributions.
3.  Round the total to **four decimal places before band assignment**.
4.  Assign the band using inclusive lower boundaries:

             Rounded score Band
  ------------------------ ----------
                 `>= 0.75` Critical
    `>= 0.50` and `< 0.75` High
    `>= 0.25` and `< 0.50` Medium
                  `< 0.25` Low

Use the configured thresholds. The table above describes the v1.0.0
defaults.

## 4. Band-floor overrides

Apply overrides **after** calculating the score and its original band.
Overrides change the final band only. Never alter `score_raw` or
`band_from_score`.

Rules:

1.  If `asset_criticality == 1.0` and `severity_score >= 0.67`, floor
    the final band at `High`.
2.  If `distinct_stages >= 3`, floor the final band at `High`.

A floor means the final band cannot be lower than the configured
`floor_band`. Preserve the rule name in `override_applied` when an
override fires.

Return all of: - `score_raw`: rounded weighted score. -
`band_from_score`: band determined by the score alone. - `band_final`:
band after overrides. - `override_applied`: the rule identifier, or
`null`.

If multiple rules fire, implement deterministic handling and retain
enough audit information to identify every fired rule. Do not allow
execution order to silently obscure which conditions were met.

## 5. Required output / audit record

The scoring result is an evidence package consumed by the interpretation
layer. The LLM must not invent explanations that are absent from this
record.

Return a structure equivalent to:

``` json
{
  "incident_id": "INC-0042",
  "model_version": "1.0.0",
  "score_raw": 0.9852,
  "band_from_score": "Critical",
  "band_final": "Critical",
  "override_applied": null,
  "factors": {
    "severity": {
      "raw": 1,
      "normalised": 1.0,
      "weight": 0.35,
      "contribution": 0.3500
    },
    "asset_criticality": {
      "raw": "server:db-01 (tier 1)",
      "normalised": 1.0,
      "weight": 0.25,
      "contribution": 0.2500
    },
    "correlation": {
      "raw": 3,
      "normalised": 1.0,
      "weight": 0.20,
      "contribution": 0.2000
    },
    "frequency": {
      "raw": 50,
      "normalised": 0.8519,
      "weight": 0.10,
      "contribution": 0.0852
    },
    "threat_intel": {
      "raw": true,
      "normalised": 1.0,
      "weight": 0.10,
      "contribution": 0.1000
    }
  },
  "data_quality": {
    "unmatched_asset": false,
    "ti_lookup_performed": true
  }
}
```

Requirements: - Include `model_version` on every scored incident. - For
each factor, retain raw input, normalised value, weight, and weighted
contribution. - Preserve data-quality indicators, including
`unmatched_asset` and whether the upstream TI lookup was performed. -
Keep enough information to explain the score and any override without
asking the LLM to reason from missing data. - Do not claim that
contribution traceability itself improves detection accuracy. It
improves auditability and explanation.

## 6. Implementation guidance

Create a small, independently testable scorer (for example,
`RiskScorer`) with responsibilities limited to:

-   Load and validate the model configuration.
-   Normalise the five supplied inputs using the fixed mappings.
-   Calculate weighted contributions and total score.
-   Assign the score-derived band.
-   Apply band-floor overrides.
-   Return the complete audit record.

Suggested normalisation functions:

``` python
import math

def normalise_severity(priority):
    return {1: 1.0, 2: 0.67, 3: 0.33}.get(priority, 0.33)

def normalise_asset(tier):
    return {
        "critical": 1.0,
        "workstation": 0.5,
        "unknown": 0.2,
    }[tier]

def normalise_correlation(stages):
    return min(1.0, stages / 3.0)

def normalise_frequency(count, cap=100):
    if count == 0:
        return 0.0
    return min(1.0, math.log10(1 + count) / math.log10(1 + cap))

def normalise_threat_intel(hit):
    return 1.0 if hit else 0.0
```

The snippets describe the reference mappings. Integrate them into the
existing NetSeer codebase rather than blindly creating duplicate modules
or parallel scoring paths. Inspect the current architecture, naming,
persistence model, and call sites first.

## 7. Reference cases

Use these as regression/unit-test fixtures:

  ------------------------------------------------------------------------
  Scenario                            Expected score Expected band
  --------------------- ---------------------------- ---------------------
  Brute force, critical                     `0.9852` Critical
  server, 3 stages, 50                               
  repeats, TI hit                                    

  Ping scan, unmatched                      `0.1955` Low
  device, 0 stages, 3                                
  repeats, no TI hit                                 

  Exploit, critical                         `0.6083` High
  server, 0 stages, 2                                
  repeats, TI hit                                    
  ------------------------------------------------------------------------

The third case is important: correlation is zero, but the weighted score
remains `0.6083` and therefore High. Do not use a multiplicative model
that drives the score toward zero when one factor is absent.

## 8. Required tests

Implement automated tests for:

1.  **Normalisation:** every factor maps to the specified value,
    including zero and cap cases.
2.  **Weight validation:** invalid or non-unit weight totals fail
    configuration loading.
3.  **Band boundaries:** test values immediately below, exactly at, and
    immediately above each threshold, after four-decimal rounding.
4.  **Overrides:** each override independently floors the band at High
    without changing the score or score-derived band.
5.  **Audit output:** all raw values, normalised values, weights,
    contributions, model version, and data-quality flags are present.
6.  **Reference scenarios:** reproduce all three expected scores and
    bands.
7.  **Monotonicity:** increasing any one normalised factor while holding
    the others fixed must not reduce the score.
8.  **Determinism:** identical inputs and configuration produce
    identical outputs.
9.  **Stable queue ordering:** sort deterministically by band rank,
    score, and timestamp. Use an explicit direction for each sort key
    and a final stable tie-breaker such as incident ID.
10. **Missing/unmatched data:** verify documented fallback behavior and
    quality flags.

## 9. Evaluation / calibration tasks

These are evaluation activities, not runtime scorer responsibilities:

-   **Weight sensitivity:** perturb each weight by `+/-20%`,
    renormalise, and report the percentage of evaluation incidents whose
    bands change.
-   **Ablation:** remove each factor in turn and report changes in band
    distribution.
-   **Expert triage agreement:** compare scorer ordering with an
    expert's ordering on a sample; calculate Spearman rank correlation.
-   **Suppression accounting:** report every incident assigned Low as a
    no-alert decision. If a true attack is suppressed, count it as a
    missed detection. Do not calculate precision only on the filtered
    population.
-   **Scenario testing:** document the expert-defined weights and
    evaluate them against representative scenarios. Treat weights as
    design parameters, not empirically optimal values.

## 10. Pitfalls to avoid

-   Do not recompute normalisation bounds from live traffic.
-   Do not band the unrounded floating-point total.
-   Do not let overrides mutate the score.
-   Do not omit the model version.
-   Do not pass only the final score/band to the LLM. Include factor
    contributions and data-quality context.
-   Do not make scoring dependent on network calls, model inference, or
    nondeterministic upstream operations.
-   Do not let queue ties produce unstable ordering.
-   Do not silently treat missing correlation as evidence of no attack.
    The specified v1.0.0 input is zero stages, but preserve data-quality
    context if correlation has not run.

## 11. Claude Code execution instructions

1.  Inspect the existing NetSeer repository and locate the current risk
    scoring, alert/incident aggregation, configuration, database schema,
    API, dashboard, and AI interpretation paths.
2.  Read the existing project documentation and follow its architecture
    and coding conventions.
3.  Identify the current scoring implementation and all call sites
    before editing. Avoid duplicate scoring logic.
4.  Implement this specification in the existing architecture with the
    smallest coherent change set.
5.  Keep detection, correlation, threat-intelligence lookup, scoring,
    and LLM interpretation as distinct responsibilities.
6.  Persist or expose the audit fields required above wherever the
    current architecture stores incident risk results. Add migrations
    only if required by the existing persistence design.
7.  Update tests and relevant documentation. Do not change unrelated
    behavior or redesign the application.
8.  Run the relevant test suite and report exact commands, results, and
    any tests that could not be run.
9.  Inspect the final diff for regressions, duplicated logic,
    undocumented assumptions, and accidental scope expansion.
10. Do not claim completion for behavior that has not been implemented
    and verified.

### Required completion report

Summarise: - Files inspected and changed. - Existing implementation
found and how it was adapted. - Scoring behavior implemented. - Tests
added and commands executed, with pass/fail results. -
Database/API/dashboard/LLM integration changes, if any. - Known gaps,
assumptions, and follow-up work.

------------------------------------------------------------------------

**Design rationale:** This is a deliberately linear, weighted-sum model.
Its monotonicity makes factor contributions interpretable, while the
audit record makes each score traceable. It is a design choice, not a
claim that the weights or thresholds are universally optimal. The AI
layer translates the deterministic result into human-readable context;
it does not make detection or risk-scoring decisions.
