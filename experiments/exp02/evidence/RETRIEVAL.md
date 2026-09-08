# EXP-02 fixed-16 retrieval and recovery record

The canonical package was acquired from the complete frozen registry on
2026-08-31 UTC. Its 255 decisions were reviewed again, and the selected plus
immediate-boundary candidates in every chosen source received a separate
candidate-specific review against the same closed eligibility rule. Public
originals, converted texts, and inspection snapshots remain local-only because
no compatible redistribution license was recorded. A Git checkout by itself
therefore cannot reproduce their exact bytes.

The final input-manifest SHA-256 is
`35d1e2af0537ea96002bdd19026d48b26c5200b6aeee6a3a287cb379b8eed680`.
It contains 16 primary documents: four each from NCSC UK, CERT-EU Threat
Intelligence, Unit 42, and ESET WeLiveSecurity. The exact hashes of the small
audit artifacts, both workbooks, and both LibreOffice smoke records are in
`sealed-evidence.sha256`. The separate candidate-specific boundary attestation
is `selection-boundary-audit.v1.json`.

## Exact preservation and recovery

The only guaranteed exact recovery method is to preserve the canonical local
sealed bytes before they are lost. The destination below must not already
exist; this avoids every exclusive-create artifact in the active evidence root.
Replace the backup destination with an absolute path on protected storage.

```bash
REPO=/path/to/tim
SEALED="$REPO/experiments/exp02/evidence"
BACKUP=/absolute/protected/path/exp02-fixed16-20260831

test -d "$SEALED/inspection"
test -d "$SEALED/inputs"
test -f "$SEALED/inspection-manifest.v1.json"
test -f "$SEALED/input-manifest.v1.json"
test ! -e "$BACKUP"
mkdir -p "$BACKUP"
cp -a "$SEALED/." "$BACKUP/"

(cd "$BACKUP" && sha256sum -c sealed-evidence.sha256)
PYTHONPATH="$REPO/experiments/exp02/src:$REPO/services/intel-extractor" \
  python3 -m exp02.cli inputs verify --root "$BACKUP"
PYTHONPATH="$REPO/experiments/exp02/src:$REPO/services/intel-extractor" \
  python3 -m exp02.cli workbooks validate --root "$BACKUP" \
  --workbook "$BACKUP/workbooks/annotator-a.xlsx"
PYTHONPATH="$REPO/experiments/exp02/src:$REPO/services/intel-extractor" \
  python3 -m exp02.cli workbooks validate --root "$BACKUP" \
  --workbook "$BACKUP/workbooks/annotator-b.xlsx"
```

The same choreography restores a protected backup into another fresh empty
root: choose a nonexistent `RESTORE`, create it, copy `"$BACKUP/."` into it,
then run the checksum, input verification, and both workbook validations with
`--root "$RESTORE"`. Never copy a backup over an existing active evidence root.

`inputs verify` checks the inspection snapshots, promoted originals/texts,
manifests, decision bindings, ledgers, source identities, and fixed selection.
The two workbook validations additionally prove 16 documents, zero entity rows,
zero relationship rows, the expected annotator identity, and the manifest bind.

## Public re-acquisition is a new attempt, not exact recovery

The public feeds and their linked pages are mutable. Re-running acquisition may
return different candidates or bytes, and therefore cannot be represented as a
guaranteed restoration. Always target a fresh temporary root and compare the
new inspection manifest before using any existing decisions:

```bash
REPO=/path/to/tim
EXPECTED_INSPECTION=8cba5f22900c792e922089b526de01c998603b703ca92ab883a64ae804a99201
REACQUIRE=$(mktemp -d /tmp/exp02-public-reacquire.XXXXXX)

cd "$REPO"
PYTHONPATH=experiments/exp02/src:services/intel-extractor \
  python3 -m exp02.cli sources inspect
PYTHONPATH=experiments/exp02/src:services/intel-extractor \
  python3 -m exp02.cli inputs inspect --root "$REACQUIRE"

ACTUAL_INSPECTION=$(sha256sum \
  "$REACQUIRE/inspection-manifest.v1.json" | cut -d ' ' -f 1)
printf 'expected=%s\nactual=%s\n' \
  "$EXPECTED_INSPECTION" "$ACTUAL_INSPECTION"
test "$ACTUAL_INSPECTION" = "$EXPECTED_INSPECTION"
```

If that final comparison fails, stop. The historical decisions are not valid
for the new bytes, and a new human review is required under a separately
authorized package revision. Even if the inspection digest happens to match,
running the ordinary CLI acquisition records a new acquisition time and need
not recreate the canonical input-manifest hash. Use the preservation workflow
above when exact identity is required.

The original live inspection used the guarded read-only TIM transport. It did
not invoke a model, Bedrock, a collector, OpenCTI mutation, annotation import,
comparison, adjudication, or reference freeze.
