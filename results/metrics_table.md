# Metrics (audited; signed off 2026-10-18)

Rates exclude parse failures. 95% CIs: 2000 bootstrap resamples of patches.

## NEUTRAL — temperature_0 (9 patches, 52 judgments)

| Condition | Metric | Rate judged defended | 95% CI | Items | Valid/total | Parse-fail |
|---|---|---|---|---|---|---|
| C1 | recognition | 55.6% | [22.2%, 88.9%] | 9 | 9/9 | 0.0% |
| C2 | false_defense | 11.1% | [0.0%, 33.3%] | 9 | 9/9 | 0.0% |
| C3 | false_defense | 11.1% | [0.0%, 33.3%] | 9 | 9/9 | 0.0% |
| C4 | false_defense | 55.6% | [22.2%, 88.9%] | 9 | 9/9 | 0.0% |
| C5 | false_defense | 0.0% | [0.0%, 0.0%] | 7 | 7/7 | 0.0% |
| C6 | recognition | 66.7% | [33.3%, 88.9%] | 9 | 9/9 | 0.0% |

| Derived | Value | 95% CI |
|---|---|---|
| cue_susceptibility_C3 | +0.000 | [+0.000, +0.000] |
| cue_susceptibility_C4 | +0.444 | [+0.000, +0.889] |
| cue_susceptibility_C5 | -0.111 | [-0.333, +0.000] |
| name_dependence | -0.111 | [-0.333, +0.000] |

| Hypothesis | Paired diff | 95% CI | Patches | CI excludes 0 |
|---|---|---|---|---|
| H1_names | +0.000 | [+0.000, +0.000] | 9 | False |
| H2_comments | +0.444 | [+0.000, +0.889] | 9 | False |
| H3_presence_vs_effect | -0.143 | [-0.500, +0.000] | 7 | False |
| H4_name_dependence | -0.111 | [-0.333, +0.000] | 9 | False |

## NEUTRAL — all_samples_pooled (9 patches, 312 judgments)

| Condition | Metric | Rate judged defended | 95% CI | Items | Valid/total | Parse-fail |
|---|---|---|---|---|---|---|
| C1 | recognition | 50.0% | [22.2%, 77.8%] | 9 | 54/54 | 0.0% |
| C2 | false_defense | 3.7% | [0.0%, 11.1%] | 9 | 54/54 | 0.0% |
| C3 | false_defense | 3.7% | [0.0%, 11.1%] | 9 | 54/54 | 0.0% |
| C4 | false_defense | 55.6% | [22.2%, 88.9%] | 9 | 54/54 | 0.0% |
| C5 | false_defense | 0.0% | [0.0%, 0.0%] | 7 | 42/42 | 0.0% |
| C6 | recognition | 53.7% | [25.9%, 81.5%] | 9 | 54/54 | 0.0% |

| Derived | Value | 95% CI |
|---|---|---|
| cue_susceptibility_C3 | +0.000 | [+0.000, +0.000] |
| cue_susceptibility_C4 | +0.519 | [+0.148, +0.889] |
| cue_susceptibility_C5 | -0.037 | [-0.111, +0.000] |
| name_dependence | -0.037 | [-0.111, +0.000] |

| Hypothesis | Paired diff | 95% CI | Patches | CI excludes 0 |
|---|---|---|---|---|
| H1_names | +0.000 | [+0.000, +0.000] | 9 | False |
| H2_comments | +0.519 | [+0.148, +0.889] | 9 | True |
| H3_presence_vs_effect | -0.048 | [-0.167, +0.000] | 7 | False |
| H4_name_dependence | -0.037 | [-0.111, +0.000] | 9 | False |

## PRIMARY — temperature_0 (9 patches, 52 judgments)

| Condition | Metric | Rate judged defended | 95% CI | Items | Valid/total | Parse-fail |
|---|---|---|---|---|---|---|
| C1 | recognition | 100.0% | [100.0%, 100.0%] | 9 | 9/9 | 0.0% |
| C2 | false_defense | 87.5% | [62.5%, 100.0%] | 9 | 8/9 | 11.1% |
| C3 | false_defense | 100.0% | [100.0%, 100.0%] | 9 | 8/9 | 11.1% |
| C4 | false_defense | 100.0% | [100.0%, 100.0%] | 9 | 9/9 | 0.0% |
| C5 | false_defense | 57.1% | [20.0%, 100.0%] | 7 | 7/7 | 0.0% |
| C6 | recognition | 100.0% | [100.0%, 100.0%] | 9 | 9/9 | 0.0% |

| Derived | Value | 95% CI |
|---|---|---|
| cue_susceptibility_C3 | +0.125 | [+0.000, +0.375] |
| cue_susceptibility_C4 | +0.125 | [+0.000, +0.375] |
| cue_susceptibility_C5 | -0.304 | [-0.667, +0.000] |
| name_dependence | +0.000 | [+0.000, +0.000] |

| Hypothesis | Paired diff | 95% CI | Patches | CI excludes 0 |
|---|---|---|---|---|
| H1_names | +0.125 | [+0.000, +0.375] | 8 | False |
| H2_comments | +0.125 | [+0.000, +0.375] | 8 | False |
| H3_presence_vs_effect | -0.333 | [-0.750, +0.000] | 6 | False |
| H4_name_dependence | +0.000 | [+0.000, +0.000] | 9 | False |

## PRIMARY — all_samples_pooled (9 patches, 312 judgments)

| Condition | Metric | Rate judged defended | 95% CI | Items | Valid/total | Parse-fail |
|---|---|---|---|---|---|---|
| C1 | recognition | 100.0% | [100.0%, 100.0%] | 9 | 54/54 | 0.0% |
| C2 | false_defense | 94.1% | [85.4%, 100.0%] | 9 | 51/54 | 5.6% |
| C3 | false_defense | 95.9% | [87.5%, 100.0%] | 9 | 49/54 | 9.3% |
| C4 | false_defense | 100.0% | [100.0%, 100.0%] | 9 | 54/54 | 0.0% |
| C5 | false_defense | 58.5% | [23.4%, 100.0%] | 7 | 41/42 | 2.4% |
| C6 | recognition | 98.1% | [94.3%, 100.0%] | 9 | 53/54 | 1.9% |

| Derived | Value | 95% CI |
|---|---|---|
| cue_susceptibility_C3 | +0.018 | [-0.006, +0.059] |
| cue_susceptibility_C4 | +0.059 | [+0.000, +0.146] |
| cue_susceptibility_C5 | -0.356 | [-0.682, +0.000] |
| name_dependence | +0.019 | [+0.000, +0.057] |

| Hypothesis | Paired diff | 95% CI | Patches | CI excludes 0 |
|---|---|---|---|---|
| H1_names | +0.019 | [+0.000, +0.056] | 9 | False |
| H2_comments | +0.056 | [+0.000, +0.130] | 9 | False |
| H3_presence_vs_effect | -0.357 | [-0.667, +0.000] | 7 | False |
| H4_name_dependence | +0.019 | [+0.000, +0.056] | 9 | False |

## PRIMARY vs NEUTRAL agreement

- temperature_0: n_pairs=50, percent_agreement=44.0%, cohens_kappa=+0.093, primary_defended_rate=92.0%, neutral_defended_rate=36.0%
- all_samples_pooled: n_pairs=302, percent_agreement=36.8%, cohens_kappa=+0.058, primary_defended_rate=92.4%, neutral_defended_rate=29.8%
