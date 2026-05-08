---
title: "A Useful Failure in Security Protocol Delta Learning"
date: 2026-05-08
draft: false
description: "The first SPDL-Linux-Lifetime baseline showed that Linux kernel publication without prior reference acquisition is often valid, forcing the project from a global rule into contextual typestate learning."
tags: ["SPDL", "Linux Kernel", "Security Research", "Research Diary"]
categories: ["Research Diary"]
---

# A Useful Failure in Security Protocol Delta Learning

## The Rule That Looked Obvious

I started the first **SPDL-Linux-Lifetime** experiment with a simple security intuition:

```text
weaker trace:
  publish_shared(o)

stronger trace:
  acquire_ref(o) → publish_shared(o)
```

The intuition was reasonable. If an object becomes shared, published, or externally reachable, perhaps the code should acquire a reference before publication.

This became the first baseline rule:

```text
prefer acquire_ref before publish
```

It looked clean. It matched the kind of historical fix I cared about. It also gave me a simple first target for Security Protocol Delta Learning.

Then real Linux kernel data rejected it.

That rejection was the most useful result so far.

---

## What SPDL Is Trying to Do

SPDL stands for **Security Protocol Delta Learning**.

The north-star idea is:

> Learn common security protocol behavior from source code, learn how historical fixes strengthen those protocols, and use that knowledge to identify current code that may be missing expected security operations.

SPDL does not try to train a simple vulnerable/non-vulnerable classifier. Confirmed vulnerabilities are rare, noisy, and difficult to label at scale.

Instead, SPDL treats source-code security learning as a **multi-representation delta problem**.

A code change is not only a raw patch diff. It can be represented as:

```text
raw source change
concrete API sequence change
abstract protocol-role change
object-aware trace change
graph/static-analysis fact change
developer explanation change
```

For example:

```diff
+ kref_get(&obj->ref);
  list_add(&obj->list, &global_list);
```

can be represented as:

```text
Concrete API delta:
  insert kref_get before list_add

Abstract protocol delta:
  publish_shared(o)
  → acquire_ref(o) → publish_shared(o)

Security meaning:
  add lifetime protection before publication
```

That was the initial vision.

---

## The First Real Linux Experiment

The first implementation focused on one narrow protocol family:

```text
Domain:
  Linux kernel

Protocol family:
  lifetime / refcount

Security point of interest:
  object publication
```

The targeted extractor scanned Linux source files containing both acquire-ref-family APIs and publish-family APIs.

The run produced:

```text
source_trace_rows: 13,426
unique_role_sequences: 1,129
publish_context_rows: 2,700
publish_with_prior_acquire_ref: 249
publish_without_prior_acquire_ref: 2,451
trainable_pairs: 249
candidate_pairs: 2,451
```

This was already a success in one important sense.

It showed that real Linux kernel source can produce trainable security-protocol objects:

```text
source code
→ concrete API sequences
→ abstract protocol-role sequences
→ publish contexts
→ weaker/stronger protocol pairs
```

The data viability hurdle was passed.

But the model result was terrible:

```text
trainable_pair_ranking_accuracy: 0.064
avg_margin: negative
```

The tiny scoring model usually preferred the supposedly weaker trace:

```text
publish_shared
```

over the supposedly stronger trace:

```text
acquire_ref → publish_shared
```

At first glance, this looked like a failure.

It was actually a correction.

---

## What Actually Failed

The failed assumption was this:

```text
publish(o) without prior acquire_ref(o) is suspicious
```

The data showed that this assumption was too broad.

Most publish contexts in the extracted Linux sample did **not** have prior `acquire_ref`:

```text
publish_with_prior_acquire_ref: 249
publish_without_prior_acquire_ref: 2,451
```

So the model was not simply broken. It was reflecting the source distribution.

In real Linux code, publication without explicit reference acquisition is often a valid typestate sequence.

That means the naive rulebook was wrong.

---

## The Corrected Understanding

The better rule is conditional:

```text
publish(o) without prior acquire_ref(o) can be valid
unless publication creates external, shared, or asynchronous reachability
that can outlive the current owner.
```

The Linux kernel has multiple valid publication typestates.

The first baseline incorrectly collapsed them into one rule.

---

## Valid Typestate 1 — Owned Container Publication

One valid pattern is ownership transfer into a container:

```text
allocate_or_obtain(o)
→ initialize(o)
→ publish_shared(o, container)
→ container_owns(o)
```

No explicit `acquire_ref` may be needed.

The object may be newly allocated and inserted into a list, tree, hash table, or other container. After insertion, the container owns the object. In that case, `publish_shared(o)` without a prior `acquire_ref(o)` is not suspicious by itself.

A trace like this may be completely valid:

```text
publish_shared → destroy
```

It may represent temporary construction, copying, cleanup, or container ownership logic, not a missing reference bug.

---

## Valid Typestate 2 — Lifetime-Protected Publication

Another valid pattern requires explicit lifetime protection:

```text
obtain(o)
→ acquire_ref(o)
→ publish_shared_or_async(o)
```

This is expected when another thread, callback, global structure, or independent observer may access the object after the current owner releases it.

This is where APIs such as the following matter:

```text
kref_get
refcount_inc
get_device
sock_hold
of_node_get
```

The issue is not publication alone. The issue is publication that creates independent reachability without a visible lifetime guarantee.

---

## Suspicious Typestate

A more meaningful suspicious pattern is:

```text
obtain(o)
→ publish_shared_or_async(o)
→ current_owner_can_release(o)
```

with no visible protection such as:

```text
acquire_ref(o)
RCU protection
parent lifetime guarantee
lock/cancellation guarantee
container ownership transfer
```

This is where a missing-protocol hypothesis becomes meaningful.

The key word is **hypothesis**.

SPDL should not say:

```text
vulnerable = true
```

It should say:

```text
This trace may be missing a lifetime-protection operation.
Here is the evidence.
Here are the false-positive checks.
```

---

## The Real Lesson

The first SPDL baseline did not fail because Linux kernel data was untrainable.

It failed because the rulebook was too simple.

The data taught this:

```text
acquire_ref before publish is not a universal rule.
It is a context-dependent security protocol.
```

That is a stronger research problem.

The next SPDL-Linux-Lifetime baseline should not ask:

```text
Is acquire_ref before publish always stronger?
```

It should ask:

```text
In which contexts is acquire_ref before publish expected?
In which contexts is publish without acquire_ref valid?
Which current traces cannot be explained by a valid no-acquire typestate?
```

---

## What Needs to Change Next

The next baseline needs contextual typestate learning.

Useful context includes:

```text
publish API
subsystem
object name
container argument
async vs shared publication
release/free path
lock/RCU context
local vs global structure
function role
historical fix evidence
```

Instead of learning a global preference:

```text
score(acquire_ref → publish) > score(publish)
```

SPDL should learn a contextual preference:

```text
score(acquire_ref → publish | context)
>
score(publish | context)
```

That is a major correction.

---

## Why This Failure Matters

This failure prevented a bad research direction.

Without this experiment, SPDL could have become a system that blindly flags thousands of valid Linux publication patterns.

That would be useless to security practitioners.

The experiment forced a better formulation:

```text
learn valid no-acquire publication typestates
and
learn when acquire_ref-before-publication is required
```

That is exactly the kind of lesson a real source-code security learning system must absorb.

---

## Updated SPDL-Linux-Lifetime Claim

SPDL-Linux-Lifetime does not assume that publication without prior reference acquisition is invalid.

Instead, it learns contextual typestate families of Linux object publication.

Some publication traces are valid ownership-transfer or container-insertion patterns. Others require explicit lifetime protection before external or asynchronous reachability.

Historical fixes provide weak directional evidence for contexts where adding `acquire_ref` before publication strengthened the protocol.

The output is not a vulnerability verdict. It is a ranked missing-protocol hypothesis for practitioner review.

---

## The Sentence I Want to Remember

The failure was useful because Linux did not reject the SPDL idea.

It rejected my oversimplified rulebook.
