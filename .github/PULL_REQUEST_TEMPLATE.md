## Summary / Scope
<!-- What changes and why. Link Issues: Closes/Refs #N (do not auto-close before approval: use "Refs") -->
Refs #

**Milestone:** M?
**In scope:**
**Explicitly out of scope:**

## Tests / Validation evidence
<!-- Commands run and results (paste output, not claims) -->
- [ ] `python3 -I -m unittest discover -s tests -v`
- [ ] `python3 -I scripts/scan_secrets.py --all`
- [ ] Markdown links verified
- [ ] Other:

## Risks
<!-- Security, privacy, data-loss, rollback considerations -->

## Security checklist
- [ ] No secrets, tokens, mailbox data or personal messages added
- [ ] No Gmail access / scope change (or explicitly approved and documented)
- [ ] No permanent-delete, send or forward capability introduced
- [ ] Email content still treated as untrusted
- [ ] No new dependency (or reviewed and justified)
- [ ] **Zero Additional Cost verified:** no billing, paid service/API/dependency, or subscription introduced

## Workflow checklist
- [ ] Feature branch, Draft until validated
- [ ] No force-push, no auto-merge
- [ ] Genuine, reviewable commits
