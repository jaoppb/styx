# Fixture E — deliberate markdown violations.

This document is supposed to fail. It carries violations from the rules that are
enforced in **both** documentation tiers, so it proves the markdown gate is live
regardless of which tier a document belongs to.

This next line is deliberately longer than the ninety-column limit that the hand-written tier enforces, so that the line-length rule is exercised too.

## What each violation proves

The heading above this paragraph, and the one at the top of the file, end in a full
stop — that is the heading-punctuation rule. The fence below carries no language,
which is the rule that catches an unlabelled code block:

```
this fence has no language tag
```

If `just gate-selftest` stops failing on this file, the markdown gate has gone
inert. Do not "fix" the fixture.

The likeliest way for that to happen is not that a rule was deleted, but that the
exclusion list quietly grew until it covered this file — or that the `--no-exclude`
flag was dropped from the self-test, at which point rumdl filters this document out
and exits 0 without reading a line of it.
