# Examples

Pre-captured CLI output for the three sample packets shipped in
`samples/`. Use these to verify the engine matches the README's
"Reproduce in 30 seconds" claims before you trust it on your own
packet.

## What you should see

| Sample | Command | Top-line expected |
|---|---|---|
| `samples/clean_packet` | `python3 mismatch_engine_ai.py samples/clean_packet` | `Confidence: CLEAN`, Aggregate Score `0.16` |
| `samples/contaminated_packet` | `python3 mismatch_engine_ai.py samples/contaminated_packet` | `Confidence: LIKELY_SYNTHETIC`, Aggregate Score `1.0` |
| `samples/templated_legitimate_packet` | `python3 mismatch_engine_ai.py samples/templated_legitimate_packet --template samples/templated_legitimate_packet/_TEMPLATE_SKELETON.md` | `Confidence: CLEAN`, Aggregate Score `0.0` |

## Files

- **`clean_packet.out.txt`**: verbatim CLI output for the clean packet.
  Shows a 15-finding run where every detector fires at or below its
  threshold.
- **`contaminated_packet.out.txt`**: verbatim CLI output for the
  contaminated packet. The PromptLeakage detector fires at 1.0 with
  three residue matches, including `[INSERT FIREWALL VENDOR HERE]`.
  ArtifactSpecificityIndex fires on mechanism-light narratives.
- **`templated_legitimate_packet.out.txt`**: verbatim CLI output for the
  templated packet with TemplateGuard active. Aggregate Score drops to
  0.00 because the template shingles are subtracted before similarity
  analysis.

## How to compare

```
python3 mismatch_engine_ai.py samples/clean_packet > /tmp/run_clean.txt
diff /tmp/run_clean.txt examples/clean_packet.out.txt
```

A clean diff means the engine shipped in this commit produces identical
output to the captured sample. If the diff is non-trivial, check the
engine version and commitment hash before proceeding.

## Drift policy

These captures were produced against commit `v0.2.0` at engine version
`0.2`. Numeric scores in the findings are deterministic given the
sample inputs. If you see drift in a score value, that is a regression
worth reporting. If you see drift in threshold constants, that is a
version change, re-capture and commit a new snapshot.

## Verify before trusting

Run the commitment verifier before trusting any output:

```
python3 verify_commitment.py
```

Expected hash: `32f1e682b0544b1af20077cc33f0604ec76238489182190c8d77a1cb01f42bbf`.
