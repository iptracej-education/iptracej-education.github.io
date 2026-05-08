---
title: "SPDL — Security Protocol Delta Learning"
date: 2026-05-07
draft: false
description: "A research framework for learning missing security-protocol operations from source code under sparse vulnerability labels."
tags: ["SPDL", "Security Research", "Program Analysis", "Machine Learning"]
categories: ["Research"]
---

SPDL — Security Protocol Delta Learning

## North-Star Vision

**SPDL aims to build a security intelligence framework that learns how software commonly satisfies security protocols, learns how historical fixes strengthen those protocols, and uses that knowledge to identify current code that may be missing expected security operations.**

The core north-star statement is:

> **SPDL treats source-code security learning as a multi-representation delta problem under sparse vulnerability labels.**

This means SPDL is not a conventional vulnerable/non-vulnerable classifier. Confirmed vulnerabilities are rare, noisy, and difficult to label at scale. Instead, SPDL learns from two more available forms of evidence:

1. **Unlabeled source-code traces**, which show commonly observed protocol behavior.
2. **Historical fixes**, which show how developers strengthened code by changing those protocols.

The long-term flow is:

```text
source-code traces
→ common protocol behavior
→ historical fix-delta signals
→ missing-protocol hypotheses
→ practitioner-readable security evidence
```

SPDL does **not** output automatic vulnerability verdicts. It outputs ranked review candidates.

---

## Core Research Claim

SPDL studies vulnerability discovery as a **missing security-protocol inference problem**.

A historical fix is represented as a before/after protocol delta. For example:

```text
weaker trace:
  publish_shared(o)

stronger trace:
  acquire_ref(o) → publish_shared(o)
```

This does not prove that every `publish_shared(o)` without `acquire_ref(o)` is vulnerable. It only tells us that, in some real repair context, adding `acquire_ref(o)` before publication strengthened the protocol.

The learning target is therefore not:

```text
code → vulnerable / non-vulnerable
```

The learning target is:

```text
source trace → common protocol behavior
historical fix → protocol-strengthening delta
current trace → possible missing protocol operation
```

---

## Program-Representation Modalities

SPDL treats source code as a **multi-representation object**. A single program behavior can be represented through several program-representation modalities:

1. Raw source text
2. Concrete API sequence
3. Abstract protocol-role sequence
4. Patch diff
5. Before/after protocol delta
6. AST / CFG / DFG / CPG graph
7. Function/callgraph context
8. Commit message / developer explanation
9. Bug report / crash trace / syzbot report
10. Historical similar fixes
11. Static-analysis facts
12. Runtime/fuzzing evidence

The same fix can therefore be represented as an aligned before/after change across multiple modalities.

Example patch:

```diff
+ kref_get(&obj->ref);
  list_add(&obj->list, &global_list);
```

### Raw source modality

```text
Before:
  list_add(&obj->list, &global_list)

After:
  kref_get(&obj->ref)
  list_add(&obj->list, &global_list)
```

### Concrete API modality

```text
Before:
  list_add

After:
  kref_get → list_add
```

### Abstract protocol-role modality

```text
Before:
  publish_shared(o)

After:
  acquire_ref(o) → publish_shared(o)
```

### Object-aware modality

```text
Before:
  publish_shared(obj)

After:
  acquire_ref(obj) → publish_shared(obj)
```

### Static-analysis fact modality

```text
Before:
  no visible lifetime-protection operation before publication

After:
  acquire_ref dominates publish_shared for the same object
```

The first implementation starts with only two modalities:

```text
1. Concrete API sequence
2. Abstract protocol-role sequence
```

Later versions can add object-aware traces, graph relations, static facts, commit messages, historical similar fixes, and runtime evidence.

---

## Why SPDL Avoids Direct Vulnerability Classification

Most vulnerability ML projects start from this framing:

```text
code → vulnerable / non-vulnerable
```

For Linux kernel research, that framing is weak because:

```text
confirmed vulnerabilities are rare
labels are noisy
safe code is not guaranteed safe
normal code may contain latent bugs
rare behavior may still be correct
models can learn shortcuts from APIs, subsystems, or commit style
```

SPDL changes the question. It asks:

```text
What security protocol behavior is common?
What historical deltas strengthened that behavior?
Where does current code appear to be missing an expected operation?
```

This turns vulnerability discovery into protocol inference and evidence ranking.

---

## First Implementation — SPDL-Linux-Lifetime

The first baseline studies Linux kernel lifetime/refcount behavior around object publication.

```text
Domain:
  Linux kernel

Protocol family:
  lifetime / refcount

Security point of interest:
  object publication
```

Initial protocol pattern:

```text
acquire_ref(o) → publish_shared(o)
acquire_ref(o) → publish_async(o)
```

Concrete API examples:

```text
acquire_ref:
  kref_get
  refcount_inc
  get_device
  sock_hold
  of_node_get

release_ref:
  kref_put
  refcount_dec
  put_device
  sock_put
  of_node_put

publish_shared:
  list_add
  list_add_tail
  hlist_add_head
  hash_add
  idr_alloc
  xa_store

publish_async:
  INIT_WORK
  queue_work
  schedule_work
  mod_timer
  timer_setup
```

---

## Baseline Research Questions

```text
RQ1:
Can Linux kernel source code produce enough protocol traces?

RQ2:
Can we build weaker/stronger protocol pairs from source traces and historical fixes?

RQ3:
Can simple models rank stronger protocol traces above weaker traces?

RQ4:
Can historical fixes provide weak directional evidence for missing-protocol hypotheses?

RQ5:
Can the system produce practitioner-readable evidence instead of only a score?
```

---

## Core Learning Object

The central learning object is a **multi-representation protocol delta pair**.

Example:

```text
weaker trace:
  publish_shared(o)

stronger trace:
  acquire_ref(o) → publish_shared(o)
```

Each pair must record its provenance:

```text
source_normal_corruption:
  created from observed source traces by removing or masking an operation

historical_fix_delta:
  created from a real before/after patch

statistical_checker_pair:
  created from high-confidence mined protocol regularities

current_hypothesis:
  created from current source code as a possible missing-operation candidate
```

Only some pair types should be used for training.

| Pair Type | Meaning | Training Use |
|---|---|---|
| Source-derived corruption pair | Strong trace observed in source; weak trace created by removing operation | Self-supervised training |
| Historical fix-delta pair | Real patch moved from weaker to stronger trace | Weak directional supervision |
| Statistical checker pair | High-confidence regularity suggests expected operation | Weak/pseudo supervision |
| Current hypothesis pair | Current code may be missing operation | Ranking/audit only, not ground truth |

This provenance is critical. It prevents the system from confusing hypotheses with verified facts.

---

## Initial Experiments

### Experiment 1 — Data Viability

Question:

> Can real Linux kernel source/history produce trainable protocol objects?

Measure:

```text
API counts
role counts
role-sequence counts
source trace counts
patch delta counts
preference/delta pair counts
```

Success means:

```text
Linux source contains many protocol traces.
Linux history contains at least some relevant fix-delta signals.
```

### Experiment 2 — Role-Sequence Learning

Question:

> Can we learn common protocol role sequences from source traces?

Start with simple models:

```text
frequency baseline
n-gram model
Markov transition model
masked-role predictor
```

Example task:

```text
Input:
  [MASK] → publish_shared

Prediction:
  acquire_ref
```

### Experiment 3 — Delta Pair Ranking

Question:

> Can the model rank stronger traces above weaker traces in the right context?

Example:

```text
stronger:
  acquire_ref → publish_shared

weaker:
  publish_shared
```

Evaluation:

```text
ranking accuracy
margin score
source-derived pair performance
historical-fix pair performance
```

### Experiment 4 — Historical Rediscovery

Question:

> When a historical fix added an operation, does the learned model also prefer the after-fix protocol trace?

Example:

```text
before:
  publish_shared

after:
  acquire_ref → publish_shared
```

Evaluation:

```text
score(after) > score(before)
missing operation ranked in top-k
historical fix appears as evidence
```

### Experiment 5 — Practitioner Evidence Packet

Question:

> Can the system produce useful review evidence?

Example output:

```text
Candidate type:
  possible missing lifetime-protection operation

Observed trace:
  publish_shared(obj)

Expected or stronger protocol candidate:
  acquire_ref(obj) → publish_shared(obj)

Concrete API evidence:
  list_add without nearby kref_get/refcount_inc/get_device/sock_hold

Historical support:
  real fixes have inserted acquire_ref before publication

False-positive checks:
  Does caller already own a stable reference?
  Is object embedded in a longer-lived parent?
  Does publication actually escape?
  Is lifetime protected by another mechanism?
```

---

## Current Lesson from Experiment 001

The first SPDL-Linux-Lifetime baseline confirmed data viability, but it also rejected the naive rulebook.

The naive assumption was:

```text
acquire_ref → publish
is globally stronger than
publish
```

Real Linux data showed that publication without prior reference acquisition is common. Therefore, `acquire_ref` before publication is not a universal rule. It is a **context-dependent typestate protocol**.

The next version must learn:

```text
When is acquire_ref before publication expected?
When is publication without acquire_ref a valid ownership-transfer or container-insertion pattern?
Which traces cannot be explained by a valid no-acquire typestate?
```

This is not a failure of SPDL. It is the first useful correction to the SPDL rulebook.

---

## What SPDL Is Not

SPDL is not:

```text
a direct zero-day detector
a fully supervised vulnerability classifier
a GNN-only project
an LLM-only project
a replacement for static analysis
an exploit-generation system
```

SPDL is:

```text
a security protocol learning framework
a weak-supervision framework using historical fixes
a multi-representation program-delta framework
a missing-protocol candidate ranking system
a practitioner evidence-generation system
```

---

## Final North-Star Statement

> **SPDL is a framework for learning missing security-protocol operations from source code. It treats source-code security learning as a multi-representation delta problem under sparse vulnerability labels. Instead of training directly on rare vulnerable/non-vulnerable examples, SPDL learns common protocol sequences from abundant unlabeled source traces and uses historical fixes as weak directional supervision. A fix is represented as a before/after delta across program-representation modalities, starting with concrete API sequences and abstract protocol-role sequences. The system ranks current code that appears to be missing expected protocol operations and produces practitioner-readable evidence rather than automatic vulnerability verdicts.**


