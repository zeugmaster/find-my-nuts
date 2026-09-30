# Product

## Register

product

## Users

Developers and proof-of-concept operators running `find-my-nuts` from a terminal while the device disseminates negligible-value Cashu proofs over Find My. They need to monitor slow, opportunistic retrieval across multiple message IDs, distinguish useful progress from stale polls, and recover complete bearer tokens without protocol guesswork.

## Product Purpose

The receiver derives the firmware's Find My candidate keys, retrieves matching reports, reconstructs framed messages, and emits a Cashu V4 token only after exact length, CRC, ASCII, and `cashuB` validation. Success means every tracked message has an understandable state, progress remains readable during long watches, completed tokens are assembled exactly, and routine polling does not create a console firehose.

## Brand Personality

Precise, calm, trustworthy. The tool should feel technically serious and quietly polished, with plain language and restrained terminal ornament.

## Anti-references

- Scrolling log firehoses that print an unchanged line every poll.
- Decorative ANSI dashboards that obscure IDs, errors, or copyable results.
- Progress communicated only through color, animation, or ambiguous icons.
- Raw symbol dumps and backend diagnostics in the normal operator path.
- Interfaces that truncate, decorate, or accidentally expose bearer tokens beyond the explicit completed-token output.

## Design Principles

1. Show state, not polling activity: keep one stable row per tracked message and update only meaningful changes.
2. Make protocol truth visible: distinguish waiting, header recovery, frame recovery, validation failure, and verified completion.
3. Treat tokens as money: validate completely, label them clearly, and keep token output directly copyable.
4. Degrade gracefully: interactive terminals may use in-place updates and optional color; redirected output must remain plain, ordered, and useful.
5. Prefer durable clarity: timestamps, message IDs, counts, and errors should remain understandable in scrollback and after interruption.

## Accessibility & Inclusion

Do not rely on color alone. Respect non-interactive output and `NO_COLOR`; keep labels textual, contrast conservative, and motion limited to replacing existing terminal rows. Support narrow terminals without corrupting output, and preserve a plain-output path suitable for logs, screen readers, and redirection.
