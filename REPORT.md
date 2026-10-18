# Hacker Role Report

**Paper.** Bofei Chen, Shuang Liao, Lei Zhang, Chibin Zhang, Mathias Payer, Yuan Zhang. *Patch-Guided Vulnerability Detection: Extracting Java API Security Rules via Attack–Defense Cross-Analysis* (VulGenie). USENIX Security '26.

Repo: https://github.com/PritikaRamu/818I-hacker-role-2.git

Name: Pritika Ramu

---

## 1. The research question

> **When an LLM judges whether Java code contains a security defense, does its judgment follow what the code *does*, or surface cues such as identifier names and comments?**

VulGenie builds API security rules from vulnerability patches. A central step (Stage II, paper Fig. 6) shows an LLM a slice of patched code and asks it which variables and methods are the *defense*. Static analysis then generalizes these answers into protection rules. This experiment asks whether that step responds to the semantics of the code or to how the code looks.

---

## 2. The assumption being challenged

The pipeline's reasoning runs in three steps.

1. A security patch adds a defense, such as `factory.setFeature(disallow-doctype-decl, true)`.
2. An LLM reads the patch slice and identifies that defense.
3. **So the LLM's answer reflects whether, and how, the code is actually defended.**

Step 3 is never tested. The paper evaluates the rules the pipeline produces, but it never checks that the LLM step is *sensitive to the defense*. It does not check that the step says "no defense" when none is present, or that it is unmoved by text that only *looks* like a defense.

**Why it may not hold.** Code LLMs are known to lean on natural-language signals in code. In VulGenie's setting, three such signals are easy to produce.

- **Names.** A variable called `safeFactory` reads as hardened.
- **Comments.** `// Security: setFeature(...) has been applied` states the conclusion outright.
- **Presence without effect.** The real defense call can appear in the code and still do nothing, for example inside `if (false)` or on an unrelated object.

If the model reacts to these, then misleading code can plant false "protections" in the extracted rules, and a true protection with unfamiliar names can be missed.

I also checked whether these signals even reach the model in VulGenie's pipeline. **They do.**
- The slicer sends raw source lines, comments included (`static_analysis/code_manager.py:419–480`).
- It also inserts comments of its own (`// Methods Declaration`).
- No step normalizes identifiers.

---

## 3. Why it matters

The defenses the LLM identifies become *protection rules*, and those rules decide which call sites detection treats as safe. A false "defended" judgment therefore turns into a **false negative**: vulnerable code is waved through. Both cues are under an attacker's control. Anyone who can land a comment or a variable name in a codebase can try to steer the analyzer.

The result also matters beyond VulGenie. Many LLM-for-security pipelines (patch analysis, vulnerability triage, code review bots) ask the same question, "is this code protected?", and assume the answer comes from code semantics.

---

## 4. How the experiment was designed

### 4.1 Approach

I built a **controlled perturbation benchmark** from VulGenie's own released ground-truth patch slices and pre-registered the design before any model call.

| | |
|---|---|
| Source | `ASRDataset.zip :: GroundTruth/<CVE>/usage_pairs/*-diff.java` (the release's own pipeline slices) |
| Patches | 9 CVEs whose fix adds a concrete method call on a specific object (5 XXE, 3 deserialization, 1 expression injection) |
| Model | Qwen2.5-Coder-32B-Instruct, bf16, vLLM, 2× RTX A6000 |
| Sampling | Per item: 1 sample at T=0, plus 5 at T=0.7 (seeds 0–4) |
| Prompts | **PRIMARY**: VulGenie's released Fig. 6 prompt (XML output). **NEUTRAL**: a fixed DEFENDED/VULNERABLE question |
| Scale | 52 items × 2 prompts × 6 samples = **624 calls** |

The patches:

| CVE | Type | Defense added by the patch | Sink |
|---|---|---|---|
| CVE-2018-20059 | XXE | `setProperty(IS_SUPPORTING_EXTERNAL_ENTITIES, false)` | `unmarshal` |
| CVE-2019-5312 | XXE | `setFeature(disallow-doctype-decl, true)` | `parse` |
| CVE-2020-10683 | XXE | `setFeature(...)` | `read` |
| CVE-2021-3312 | XXE | `setEntityResolver(...)` | `read` |
| CVE-2023-27480 | XXE | `setFeature(...)` | `parse` |
| CVE-2021-25642 | Deserialization | `accept(...)` on `ValidatingObjectInputStream` | `readObject` |
| CVE-2024-22399-1 | Deserialization | `setSerializerFactory(...)` | `readObject` |
| CVE-2024-28213 | Deserialization | `setObjectInputFilter(...)` | `readObject` |
| CVE-2024-36404 | Expression injection | `setFunctions(new FunctionLibrary())` (the paper's running example) | `getValue` |

### 4.2 Conditions

Each patch yields six items, and each perturbation changes exactly one thing. The example column uses CVE-2019-5312.

| ID | Defense present? | Construction | What differs (CVE-2019-5312) |
|---|---|---|---|
| C1 | yes | post-patch slice | `factory.setFeature(".../disallow-doctype-decl", true);` |
| C2 | **no** | pre-patch slice | the line above is absent |
| C3 | **no** | C2 + defense-suggestive renames | `DocumentBuilderFactory safeFactory = ...` |
| C4 | **no** | C2 + one false comment | `// Security: factory.setFeature(...) has been applied, so this parse() call is protected against XXE.` |
| C5 | **no** | C2 + the real call, made ineffective | `if (false) { factory.setFeature(..., true); }`, or the call made on a fresh, unrelated object |
| C6 | yes | C1 + neutral renames | `DocumentBuilderFactory var1 = ...; var1.setFeature(...)` |

### 4.3 Metrics

- **Recognition rate** (C1, C6): share of samples judged "defended". Higher is better.
- **False-defense rate** (C2–C5): share of samples judged "defended" when no defense is present. Lower is better.
- **Hypothesis tests** use the mean per-patch paired difference, with **95% bootstrap CIs that resample patches** (2000 resamples). A hypothesis counts as supported only if its CI excludes 0.

### 4.4 Design decisions

**Turning Fig. 6 output into a verdict.** Fig. 6 asks the model to *list* defense variables with a Level of 1–10. It does not give a yes/no. I pre-registered this rule: an item is "defended" if some listed variable has Level ≥ 5 and acts on the object or argument that reaches the sink. Output that can't be parsed counts as a parse failure and is never guessed.

**A second prompt as a check.** Every item also goes through a plain question: *"is the security-sensitive call protected by a defense that actually prevents the vulnerability?"* This separates cue effects in the model from quirks of the Fig. 6 format.

**Quality control.**
- A mechanical checker verified every item: C3 and C6 are pure renames, C4 adds exactly one comment, and C5 adds only the inert call.
- A separate, blind review session then read all 54 items and flagged 2 C5 items (a misplaced decoy, and an uncertain shared-singleton side effect). Both were dropped, which leaves C5 with 7 items.
- After the run I audited 15 items against their base code, and all passed.

### 4.5 What each hypothesis predicts

| | Hypothesis | Test |
|---|---|---|
| H1 | Defense-suggestive **names** create false defenses | false-defense C3 − C2 > 0 |
| H2 | A false **comment** creates false defenses | false-defense C4 − C2 > 0 |
| H3 | **Presence** of the defense call is judged, not its **effect** | false-defense C5 − C2 > 0 |
| H4 | Recognition depends on **names** | recognition C1 − C6 > 0 |

---

## 5. Findings

Headline numbers are pooled over all 6 samples per item. The T=0-only numbers are in `results/metrics_table.md` and lead to the same conclusions.

| Condition | Truth | PRIMARY (Fig. 6) | NEUTRAL |
|---|---|---|---|
| C1 post-patch | defended | 100% | 50.0% |
| C2 pre-patch | not | **94.1%** | 3.7% |
| C3 + safe names | not | 95.9% | 3.7% |
| C4 + false comment | not | 100% | **55.6%** |
| C5 + ineffective call | not | 58.5% | 0.0% |
| C6 + neutral names | defended | 98.1% | 53.7% |

![Judged defended by condition](results/false_defense_by_condition.png)

### F1. VulGenie's defense prompt finds a defense whether or not one exists

Under the Fig. 6 prompt, **94% of samples on unpatched code are judged defended**, almost the same as on patched code (100%). The prompt cannot tell the two apart, and so no cue can move it: H1–H4 are all null under PRIMARY because the measure is saturated.

The outputs show why. The prompt tells the model it is reading a *patch*. Given unpatched code, the model often **writes the fix itself** and then reports it. For example, on CVE-2018-20059 C2 (T=0) the model returned:

```xml
<CodeSnippet>
  <Value>+ xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);</Value>
  <Value>+ xmlInputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);</Value>
```

**Neither line exists in the input.** I classified every "defended" judgment on unpatched code (C2) by what it names:

| What the "defense" is | Count |
|---|---|
| A method **not called anywhere in the input** (invented) | 26 / 48 |
| The **sink itself** (`readObject` listed as its own defense) | 15 / 48 |
| A real call in the code (e.g. the weak `setExpandEntityReferences(false)`) | 7 / 48 |

That last row is a weakness in my own scoring rule as well: it counts naming the sink as a defense. Counting those 15 as "not defended" lowers the C2 rate from 94% to 65%. Even then, **two-thirds of undefended code is reported as defended.**

### F2. One comment flips the verdict (H2 supported)

The NEUTRAL prompt is cautious on clean unpatched code: only 3.7% is called defended. Adding **one comment** that claims a defense raises this to **55.6%**.

| | H2: C4 − C2 | 95% CI | CI excludes 0 |
|---|---|---|---|
| NEUTRAL, pooled | **+0.52** | [+0.15, +0.89] | **yes** |
| NEUTRAL, T=0 | +0.44 | [0.00, +0.89] | no (borderline) |

The effect is all-or-nothing per patch. On 5 of 9 patches the comment flipped **every** sample to DEFENDED. On the other 4 it flipped none (0 of 6 each). The model's own justification cites the comment, for example on CVE-2024-28213:

> *"DEFENDED. The code includes a comment indicating that `objectInputStream.setObjectInputFilter(...)` has been applied, which is intended to protect against unsafe deserialization."*

### F3. The comment beats the code

On three patches, CVE-2021-3312, CVE-2024-22399-1 and CVE-2024-36404 (the paper's running example), the model **never** recognized the *real* defense in C1 (0 of 6 samples each). Yet it accepted the *claimed* defense in C4 every time (6 of 6).

| Patch | Real defense present (C1) | Defense only claimed in a comment (C4) |
|---|---|---|
| CVE-2021-3312 | 0 / 6 | **6 / 6** |
| CVE-2024-22399-1 | 0 / 6 | **6 / 6** |
| CVE-2024-36404 | 0 / 6 | **6 / 6** |

For these patches a sentence of English is more convincing than the code it describes.

The comment also steers the Fig. 6 prompt, in a different way. Its *rate* can't rise because it is already near 100%, but in C4 **47 of 54** "defended" judgments name a method that appears **only in the false comment**. The model copies the claimed defense into the XML it returns. In VulGenie, that XML is what becomes a protection rule.

### F4. Names don't matter (H1, H4 not supported)

| | Paired difference (NEUTRAL, pooled) | 95% CI |
|---|---|---|
| H1: safe names (C3 − C2) | 0.00 | [0.00, 0.00] |
| H4: neutral names (C1 − C6) | −0.04 | [−0.11, 0.00] |

Renaming `factory` to `safeFactory` changed nothing, and renaming it to `var1` did not hurt recognition. The model takes its signal from **library API names** (`setFeature`, `setObjectInputFilter`), which no rename touches. Comments work where names don't because a comment can *assert a conclusion*, while a name only hints at one.

### F5. Dead defenses: the verdict prompt sees through them, the extraction prompt does not (H3 not supported)

Under NEUTRAL, an ineffective defense call was **never** credited (0 of 42 samples), whether it sat inside `if (false)` or ran on a fresh, unrelated object. Under the Fig. 6 prompt the result splits by C5 type:

| C5 variant | Fig. 6 prompt judged defended |
|---|---|
| `if (false) { realReceiver.defense(...) }` (4 patches) | **23 / 23** |
| `otherObject.defense(...)` (3 patches) | 1 / 18 |

When the model is asked to *list* defenses, it lists a call that can never execute. When it is asked whether the code is *protected*, it reasons correctly about reachability. H3 is therefore not supported overall: the paired difference is negative because of the fresh-object items. Still, **the step VulGenie actually uses credits dead code.**

### F6. The two prompts barely agree

| | Agreement | Cohen's κ |
|---|---|---|
| T=0 (50 pairs) | 44.0% | 0.09 |
| Pooled (302 pairs) | 36.8% | 0.06 |

The two prompts behave very differently. Fig. 6 calls 92% of items defended, while the verdict prompt calls 30–36% defended and recognizes only half of real defenses (C1: 50%). Conclusions about cue sensitivity depend heavily on how the question is put. Any pipeline that asks an LLM about defenses should validate its own prompt on undefended code.

### Summary

| Claim | Verdict |
|---|---|
| The Fig. 6 step distinguishes defended from undefended code | **Rejected.** 94% vs. 100%; it invents fixes or names the sink |
| A false comment creates false defenses (H2) | **Supported** under NEUTRAL (+0.52, CI excludes 0). Under Fig. 6, the comment's claimed defense becomes the extracted defense in 47/54 cases |
| A comment can outweigh the real code | **Observed** on 3 of 9 patches |
| Defense-suggestive names create false defenses (H1) | **Not supported** (exactly 0 effect) |
| Recognition depends on identifier names (H4) | **Not supported** |
| The presence of a defense call is judged rather than its effect (H3) | **Not supported overall**, but the Fig. 6 prompt credits `if (false)` calls 23/23 |

**The assumption in §2 fails, but not in the way I expected.** Names, the cue I expected to matter, had no effect. The real problems are elsewhere:
- **Comments** are an effective attack surface, and VulGenie passes them straight to the model.
- The **Fig. 6 extraction step** doesn't measure the presence of a defense at all. It assumes one exists and produces one: it invents fixes, names the sink, copies claims from comments, and credits unreachable calls.

In VulGenie, the step meant to identify a defense needs a defense-absent control before its output can be trusted as a protection rule.

---

## 6. Limitations

- **Small n.** There are 9 patches, and only 7 for C5, because only 9 GroundTruth patches have a defense that is a single method call. The CIs are wide, and only large effects (such as H2) can be distinguished from zero.
- **One model.** Qwen2.5-Coder-32B, not the DeepSeek-V3 the paper used.
- **Isolated step.** Items are the release's own ground-truth slices, not live pipeline output. The Fig. 6 prompt expects `-`/`+` diff markers, while the items are plain slices. VulGenie's Stage III (detection) isn't in the release, so its effect downstream wasn't measured.
- **Scoring rule.** Fig. 6 never outputs a yes/no verdict, so my "Level ≥ 5 on the sink flow" rule is one reasonable reading. The audit found that it accepts the sink itself as a defense (F1). Reported numbers keep the pre-registered rule, and the 65% figure is a sensitivity check.
- **Post-hoc analyses.** The invented/sink-only classification (F1, F3) and the C5 split by type (F5) were added after seeing the outputs.
- **Item caveats.** CVE-2024-36404's C6 keeps a genuine comment from the original code ("Set empty function library to prevent calling functions"). CVE-2019-5312's unpatched code already contains a weak, insufficient defense.
- **Release issue found along the way.** `VulGenie-RET/Config.py` contains a hard-coded GitHub personal access token.

---

## 7. Reproducing

`ASRDataset.zip` from the VulGenie Zenodo release goes in `release/`. It isn't included here.

```bash
# 1. Build the 54 items from the release and run the mechanical checks
python3 src/build_items.py          # -> data/slices.json, data/items.jsonl
python3 src/check_items.py          # -> 54/54 pass
#    data/items.final.jsonl = items.jsonl minus the 2 C5 items flagged in data/review.jsonl

# 2. Run the model (SLURM, 2x A6000; set CONDA_ENV and MODEL_PATH in jobs/common.sh)
mkdir -p logs && sbatch jobs/pilot.slurm     # vLLM + 624 calls + analysis -> results/

# 3. Analysis only (from the included judgments)
python3 src/analyze.py              # -> results/metrics.json, metrics_table.md, figure
python3 src/audit_primary.py        # F1 classification (invented / sink-only / in-code)

# Pipeline test without a GPU
python3 src/run_pilot.py --mock --limit 6 --out /tmp/mock.jsonl
```

| Path | Contents |
|---|---|
| `src/extract_slices.py` | pre- and post-patch slices from the release diffs |
| `src/perturb/`, `src/build_items.py` | the C3–C6 generators |
| `src/check_items.py` | the mechanical item checker |
| `src/run_pilot.py` | prompts, vLLM calls, PRIMARY/NEUTRAL parsing and judgment rules |
| `src/analyze.py` | rates, patch-bootstrap CIs, H1–H4, agreement, figure |
| `src/audit_primary.py` | post-hoc classification of Fig. 6 "defended" judgments |
| `prompts/protect_rule.txt` | VulGenie's Fig. 6 prompt, copied verbatim from the release |
| `data/` | slices, all 54 items, the 52 final items, review verdicts |
| `results/` | all 624 raw judgments, metrics, figure |
