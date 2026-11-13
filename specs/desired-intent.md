# Desired intent: Sanitized workflow communication

Status: engineering direction and acceptance obligations, not a new implementation
claim, grant of authority, or replacement for existing versioned contracts.

## System intent and evidence boundary

Runspindle is intended to turn an authorized one-off task into a repeatable,
maintained workflow by composing scoped access, managed native/browser sessions,
explicit human takeover, and evaluated workflow candidates. The useful capability
is the composition: cross-application execution can retain identity and evidence
across interruptions, while approved examples can inform later DSPy experiments.
This is a design objective, not evidence of emergent intelligence, autonomous
self-improvement, deployed integration, or measured gains.

A workflow revision must identify its inputs, permitted effects, target bindings,
exception policy, acceptance criteria and resource budget. Repetition does not
create a recurring schedule or expand permission. Human intervention is first an
execution event; only a separately reviewed, consented and sanitized example may
enter a dataset. A successful evaluation is evidence for review, not authority to
promote, serve, spend, publish or act in another account.

## Component responsibility

Tether should connect authorized collaboration to ongoing workflow state while
preserving the existing integration boundary. A conversational message can request
work or provide a correction, but channel membership, quoted text and a thread ID
are not sufficient authority to control accounts or approve candidate promotion.
The intended benefit is continuity of task context and trustworthy status, not
unrestricted mirroring of every native event.

## Interfaces and acceptance obligations

- Preserve authenticated sender, workspace/channel/thread/message/event identity
  and task revision/native-session attribution. Bind each outgoing receipt to its
  permitted destination; correlation metadata must not expand its audience.
- Reconcile duplicate events, edits, deletions and uncertain deliveries. Accepted
  transport submission is not delivered; use stable delivery identity and trusted
  readback rather than blindly posting again after timeouts.
- Sanitize before transmission. Send minimal supported status and artifact
  references only under sharing authority; omit credentials, account contents,
  control handles, hidden reasoning and raw private desktop/session streams.
- Treat incoming content and suggested corrections as untrusted data until sender,
  scope and operation authority are verified. Feedback approval and execution
  approval are distinct; neither a reaction nor an evaluation score universally
  authorizes future work.
- Integrate supported exposed runtime events through existing Tether/RepoFleet
  seams rather than creating a parallel Slack subsystem. Use fake transports and
  synthetic identities for public tests, including destination mistakes, duplicate
  delivery, stale edits, cancellation and unknown outcomes.

## Present scope

This repository contains contracts and synthetic fixture consumers, not an
implemented runtime adapter or all-session live mirror. Existing final-output
forwarding cannot be presented as full event coverage. See
[Slack events](slack-events.md) and [mirroring acceptance](../docs/MIRRORING_ACCEPTANCE.md).
