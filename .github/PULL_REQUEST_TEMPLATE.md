## What and why

<!-- One short paragraph: what this changes and why it is needed. -->

## Checklist

- [ ] `moon fmt` clean
- [ ] `moon check --target all --deny-warn` passes
- [ ] `moon test` passes on the backends your change touches
- [ ] New or changed behavior has tests; parser/packet paths include malformed input
- [ ] `scripts/interop_check.sh` run if wire format or key handling changed
