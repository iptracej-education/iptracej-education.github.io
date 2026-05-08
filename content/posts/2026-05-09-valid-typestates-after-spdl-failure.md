---
title: "Valid Typestates After a Useful Failure in SPDL-Linux-Lifetime"
date: 2026-05-09
draft: false
description: "The first SPDL-Linux-Lifetime experiment showed that publication without prior reference acquisition is often valid in Linux kernel code. This post explains the valid typestate families the model must learn before it can rank missing lifetime-protocol candidates."
tags: ["SPDL", "Linux Kernel", "Typestate", "Security Research", "Program Analysis"]
categories: ["Research Diary"]
---



# Valid Typestates After a Useful Failure in SPDL-Linux-Lifetime

The first SPDL-Linux-Lifetime baseline taught a useful lesson: my initial rulebook was too simple.

I started with this intuition:

```text
weaker trace:
  publish_shared(o)

stronger trace:
  acquire_ref(o) -> publish_shared(o)
```

The idea was reasonable at first glance. If an object becomes shared or externally reachable, perhaps the code should acquire a reference before publication.

But the Linux kernel data pushed back.

After targeting files that contained both lifetime/refcount APIs and publication APIs, the baseline extracted:

```text
source_trace_rows: 13,426
unique_role_sequences: 1,129
publish_context_rows: 2,700
publish_with_prior_acquire_ref: 249
publish_without_prior_acquire_ref: 2,451
trainable_pairs: 249
candidate_pairs: 2,451
```

The naive model then performed badly:

```text
trainable_pair_ranking_accuracy: 0.064
avg_margin: negative
```

That result looked like failure. It was actually the first important discovery.

The failure means this rule is wrong:

```text
publish(o) without prior acquire_ref(o) = suspicious
```

Linux has many valid publication patterns that do not require explicit reference acquisition. The right research problem is not to blindly prefer `acquire_ref -> publish`. The right problem is to learn **which typestate family a publication belongs to**.

This post defines the valid typestate families that the next SPDL-Linux-Lifetime baseline needs to understand.

---

## Why the Original Rule Was Too Broad

The original rulebook treated publication as if it always meant external reachability:

```text
publish_shared(o)
```

and assumed the stronger sequence should be:

```text
acquire_ref(o) -> publish_shared(o)
```

But publication is overloaded in real systems code.

A list insertion may mean:

```text
ownership transfer into a container
```

or:

```text
temporary local list construction
```

or:

```text
publication of a parent object whose lifetime already dominates the child
```

or:

```text
RCU-protected publication
```

or:

```text
asynchronous publication that really does require lifetime protection
```

Those are different typestates. A single global rule cannot distinguish them.

The corrected rule is:

```text
publish(o) without prior acquire_ref(o) can be valid
if another lifetime explanation exists.

publish(o) becomes suspicious when the object becomes externally or asynchronously reachable
and may outlive the current owner without a visible lifetime guarantee.
```

---

## Valid Typestate 1 — Owned Container Publication

In this pattern, the object is newly allocated and inserted into a container that becomes responsible for its lifetime. No extra `kref_get()` is needed because ownership is being transferred into the container.

This is a simplified Linux-style example, not a direct excerpt from a specific kernel file.

```c
struct item {
    struct list_head node;
    int state;
};

struct item *item_create_and_add(struct list_head *head)
{
    struct item *item;

    item = kzalloc(sizeof(*item), GFP_KERNEL);
    if (!item)
        return NULL;

    INIT_LIST_HEAD(&item->node);
    item->state = ITEM_READY;

    /*
     * Publication into the container.
     * The container now owns the object.
     * This does not necessarily require kref_get().
     */
    list_add_tail(&item->node, head);

    return item;
}
```

Role sequence:

```text
allocate(o)
-> initialize(o)
-> publish_shared(o, container)
-> container_owns(o)
```

This is a valid no-acquire publication pattern.

The naive SPDL rule would incorrectly treat this as suspicious:

```text
publish_shared(o) without acquire_ref(o)
```

But the better interpretation is:

```text
ownership is transferred into the container
```

The next model should learn this as a valid typestate family.

---

## Valid Typestate 2 — Local or Private List Construction

Not every `list_add()` publishes an object to the outside world. Sometimes a list is only a local construction structure.

```c
static int build_local_list(void)
{
    LIST_HEAD(local_items);
    struct item *item;
    int ret = 0;

    item = kzalloc(sizeof(*item), GFP_KERNEL);
    if (!item)
        return -ENOMEM;

    INIT_LIST_HEAD(&item->node);
    item->state = ITEM_READY;

    /*
     * This is a local/private list.
     * The object is not escaping to a global owner,
     * another thread, or an asynchronous callback.
     */
    list_add(&item->node, &local_items);

    ret = process_items(&local_items);

    list_del(&item->node);
    kfree(item);

    return ret;
}
```

Role sequence:

```text
allocate(o)
-> initialize(o)
-> publish_shared(o, local_container)
-> use(o)
-> unpublish(o)
-> destroy(o)
```

This is valid without `acquire_ref`.

The missing concept is that not every publication API is a security-sensitive publication. Some list operations are local organization, temporary batching, or construction.

The rulebook must distinguish:

```text
local/private publication
```

from:

```text
external/shared/asynchronous publication
```

---

## Valid Typestate 3 — Parent-Dominated Lifetime

Sometimes the published element is embedded inside a longer-lived parent object. The child or list node does not need a separate reference acquisition if the parent lifetime dominates the published field.

```c
struct child {
    bool ready;
};

struct parent {
    struct child child;
    struct list_head node;
};

void parent_register(struct parent *p, struct list_head *global_list)
{
    INIT_LIST_HEAD(&p->node);
    p->child.ready = true;

    /*
     * The list node belongs to the parent object.
     * The child lifetime is protected by the parent lifetime.
     */
    list_add_tail(&p->node, global_list);
}
```

Role sequence:

```text
parent_lifetime_exists(parent)
-> initialize(child)
-> publish_shared(parent)
-> child_lifetime_dominated_by(parent)
```

This is a valid no-acquire publication pattern.

The lifetime guarantee does not come from:

```text
acquire_ref(child)
```

It comes from:

```text
parent lifetime dominates child lifetime
```

A model that only sees `list_add_tail()` without `kref_get()` will misunderstand this case unless it learns object containment and parent lifetime.

---

## Valid Typestate 4 — RCU-Protected Publication

Some kernel objects are protected by RCU rather than explicit reference acquisition before publication.

```c
struct object __rcu *global_obj;

void publish_rcu_object(struct object *obj)
{
    obj->ready = true;

    /*
     * Publication is protected by RCU semantics,
     * not by kref_get().
     */
    rcu_assign_pointer(global_obj, obj);
}

void use_rcu_object(void)
{
    struct object *obj;

    rcu_read_lock();

    obj = rcu_dereference(global_obj);
    if (obj)
        use_object(obj);

    rcu_read_unlock();
}
```

Role sequence:

```text
initialize(o)
-> rcu_publish(o)
-> rcu_read_lock()
-> rcu_dereference(o)
-> use(o)
-> rcu_read_unlock()
```

This shows why the rulebook cannot only ask:

```text
Was acquire_ref before publish?
```

It must also ask:

```text
Is another lifetime-protection mechanism present?
```

For RCU-protected paths, the expected protocol is not necessarily:

```text
acquire_ref(o) -> publish_shared(o)
```

It may be:

```text
rcu_assign_pointer(o)
-> rcu_dereference(o) inside rcu_read_lock()
```

---

## Valid Typestate 5 — Lock-Scoped Publication

Some publication is valid because the object or container is protected by a lock, and the access discipline prevents unsafe observation.

```c
struct registry {
    struct mutex lock;
    struct list_head items;
};

void registry_add(struct registry *reg, struct item *item)
{
    mutex_lock(&reg->lock);

    /*
     * The object is inserted while the registry lock is held.
     * Readers must also hold the same lock.
     */
    list_add_tail(&item->node, &reg->items);

    mutex_unlock(&reg->lock);
}
```

Role sequence:

```text
acquire_lock(l)
-> publish_shared(o, locked_container)
-> release_lock(l)
```

This does not by itself prove lifetime safety, but it is a different typestate from uncontrolled publication.

The model should not reduce everything to:

```text
missing acquire_ref
```

It should represent:

```text
publication occurs under lock discipline
```

and then ask whether that lock discipline is sufficient for the object lifetime and access pattern.

---

## Lifetime-Protected Publication

There are still contexts where explicit reference acquisition before publication is the stronger protocol.

This is especially important when an object is handed to another thread, callback, workqueue, timer, global structure, or independent observer that may outlive the current owner.

```c
struct object {
    struct kref ref;
    struct work_struct work;
};

void queue_object_work(struct object *obj)
{
    /*
     * The workqueue may run after the current caller returns.
     * Take a reference before asynchronous publication.
     */
    kref_get(&obj->ref);

    INIT_WORK(&obj->work, object_work_fn);
    queue_work(system_wq, &obj->work);
}

static void object_work_fn(struct work_struct *work)
{
    struct object *obj;

    obj = container_of(work, struct object, work);

    use_object(obj);

    kref_put(&obj->ref, object_release);
}
```

Role sequence:

```text
obtain(o)
-> acquire_ref(o)
-> publish_async(o)
-> async_use(o)
-> release_ref(o)
```

This is the kind of sequence my original SPDL rule was trying to capture.

The corrected lesson is:

```text
acquire_ref before publish is not universally required,
but it is expected in contexts where publication creates independent lifetime risk.
```

---

## Suspicious Typestate — Publication May Outlive the Current Owner

The suspicious case is not simply “publication without reference acquisition.”

The suspicious case is publication where another execution context may use the object after the current owner releases it.

```c
struct object {
    struct kref ref;
    struct work_struct work;
};

void queue_object_work_buggy(struct object *obj)
{
    INIT_WORK(&obj->work, object_work_fn);

    /*
     * The object is published to an asynchronous worker,
     * but no visible lifetime protection is acquired.
     */
    queue_work(system_wq, &obj->work);

    /*
     * If the current owner can release obj before the worker runs,
     * the worker may later dereference a stale object.
     */
    kref_put(&obj->ref, object_release);
}

static void object_work_fn(struct work_struct *work)
{
    struct object *obj;

    obj = container_of(work, struct object, work);

    use_object(obj);
}
```

Role sequence:

```text
obtain(o)
-> publish_async(o)
-> release_ref(o)
-> async_use(o)
```

Potential missing protocol operation:

```text
insert acquire_ref(o) before publish_async(o)
```

This is the real SPDL candidate shape.

Not every `publish_async(o)` without `acquire_ref(o)` is a bug. But this shape is worth ranking and reviewing when no other lifetime explanation is visible.

---

## The Corrected Rulebook

The first rule was too broad:

```text
publish(o) without prior acquire_ref(o) = suspicious
```

The corrected rule is contextual:

```text
publish(o) without prior acquire_ref(o) can be valid
if ownership is transferred,
the list is local/private,
the object is embedded in a longer-lived parent,
another lifetime mechanism such as RCU protects the object,
or lock/cancellation/join discipline explains the lifetime.

publish(o) becomes suspicious when the object becomes externally or asynchronously reachable
and may outlive the current owner without a visible lifetime guarantee.
```

So the next SPDL-Linux-Lifetime baseline should not learn one global preference:

```text
acquire_ref -> publish > publish
```

It should learn contextual typestate families:

```text
owned_container_publication
local_private_publication
parent_lifetime_publication
rcu_protected_publication
lock_scoped_publication
lifetime_ref_protected_publication
unresolved_publication_needs_review
```

---

## What the Model Should Learn Next

The next model should ask:

```text
Given this publication context, which typestate family does it resemble?
```

Possible outputs:

```text
owned container publication
local/private construction
parent-dominated lifetime
RCU-protected publication
lock-scoped publication
lifetime-ref protected publication
unresolved publication needing review
```

This requires more context than the first baseline used.

Useful features include:

```text
publish API
publish role: shared vs async
subsystem
function name
object name
container argument
presence of release/free after publication
lock context
RCU context
local vs global structure
historical fix similarity
```

This is where SPDL becomes more interesting.

The first experiment proved that Linux can produce protocol traces. The failure proved that a global rule is not enough.

The next research step is contextual typestate learning.

---

## Why This Matters

The useful failure prevented a bad tool.

A naive tool would have treated 2,451 `publish_without_prior_acquire_ref` traces as suspicious candidates. That would be noisy and mostly useless.

A better SPDL system should first learn why many of those traces are valid.

Only then should it rank the traces that remain unexplained.

That is the deeper lesson:

```text
Before learning missing security operations,
we must learn valid security typestates.
```

The Linux kernel did not reject SPDL.

It rejected the oversimplified rulebook.
