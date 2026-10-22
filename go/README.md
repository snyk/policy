# dotsnyk

A Go library for reading and writing `.snyk` policy files.

This is the Go half of this repo. The TypeScript library in [`lib/`](../lib) is the
older, more complete one; see the [root README](../README.md).

## Install

```bash
go get github.com/snyk/policy/go
```

```go
import "github.com/snyk/policy/go/dotsnyk"
```

The module path is `github.com/snyk/policy/go` — note the `/go` suffix. It is a
subdirectory module, so its releases are tagged `go/vX.Y.Z` and are independent
of the npm `vX.Y.Z` tags that `snyk-policy` uses.

Requires Go 1.25.12 or later. The floor is that specific rather than `1.25`
because 1.25.12 is the first release fixing CVE-2026-39822 in `std/os`; nothing
in the library needs a language feature newer than 1.24.

## What it does

Parses a `.snyk` file into a `Policy`, and writes one back out. It reads from an
`io.Reader` and writes to an `io.Writer`; opening the file is the caller's job.

```go
fd, err := os.Open(".snyk")
if err != nil {
    return err
}
defer fd.Close()

p, err := dotsnyk.Unmarshal(fd)
if err != nil {
    return err
}

reason := "no fix available"
expires := time.Now().AddDate(0, 1, 0)
p.AddIgnore("SNYK-JS-LODASH-567746", []string{"express", "lodash"}, &dotsnyk.Rule{
    Reason:  &reason,
    Expires: &expires,
})

return dotsnyk.Marshal(os.Stdout, p)
```

The model mirrors the YAML document as it is written rather than presenting a
friendly view of it. `Policy.Ignore` and `Policy.Patch` are
`map[VulnID][]RuleEntry`, where a `RuleEntry` is itself a
`map[string]*Rule` keyed by dependency path — the same nesting the file has,
including the sequence layer that almost always holds exactly one element. If
you want a flat list of ignores, you build it yourself for now.

Timestamps are parsed leniently: RFC 3339 with and without a zone,
space-separated, and date-only forms are all accepted.

## Rules that cannot be read

A problem inside one rule does not fail the file. `Unmarshal` returns every
other rule and lists what it could not read in `Policy.Warnings`, each with the
vulnerability ID, dependency path, line and reason:

```go
for _, w := range p.Warnings {
    log.Println(w)
}
// line 6: skipped ignore rule for SNYK-JS-CXCT-535487 at '*': expires: 'not-a-date' is not a valid timestamp
```

- **`SkippedRule`.** A dependency path is left out of `Ignore` or `Patch` when
  its `expires` or `disregardIfFixable` cannot be read. Both fields decide what
  the rule hides and for how long, so guessing them could hide an issue
  indefinitely. The issue is reported instead, and the other paths in the same
  list item still apply. A list item that is not shaped like a rule, such as an
  under-indented one, is left out whole. A vulnerability with no readable rules
  left is left out too.
- **`DroppedField`.** The rule is kept without the field when a descriptive
  field cannot be read: `reason`, `reasonType`, `source`, `from`, `ignoredBy`,
  `created` or `patched`.

Problems with the file as a whole still return an error: invalid YAML, tab
indentation, a top level or rule set that is not a mapping, a vulnerability ID
that does not map to a list, the old `.snyk` format, a duplicate vulnerability
ID or rule field, and a vulnerability ID or rule field that is not a string.

## Status

Lifted from [`cli-extension-os-flows`](https://github.com/snyk/cli-extension-os-flows)
`pkg/localpolicy` so that the parser has one open-source home. Accepted
timestamp formats and coercions are what the CLI has been shipping. Since then, a
problem inside one rule no longer fails the whole file, as described above. The
entry points were reshaped on review:
`Unmarshal` returns `(*Policy, error)` rather than filling in a caller-supplied
pointer, and the path-based `Load` helper did not come across, since a library
that takes an `io.Reader` has no reason to own file opening.

It is **not** at parity with the TypeScript implementation in `lib/`. The two
agree on the fixtures in `test/fixtures/`, which both are tested against, and on
every well-formed file we know of. They diverge on malformed and unusual input,
almost always with `dotsnyk` being the stricter of the two:

| Input | `dotsnyk` | TypeScript `lib/` |
| --- | --- | --- |
| Top-level scalar or sequence | error, `policy must be a mapping` | empty policy, no error |
| Non-list `patch` entry | error, `old, unsupported .snyk format detected` | entry dropped, no error |
| `expires: not-a-date` | rule skipped, reported in `Policy.Warnings` | kept as a string and compared to the current time as text |
| `expires: '...+02:00'` | offset preserved | JS `Date`, normalised to UTC |
| Date-only, space-separated, zone-less timestamps | accepted via a fixed format list | accepted via JS `Date` parsing |
| `reason: 5` | coerced to `"5"` | untyped, passes through |
| `ignoredBy: someone`, `reason: [a, b]` | field dropped, rule kept, reported in `Policy.Warnings` | untyped, passes through |
| `version: v2.0.0` | accepted | error |
| `version: 1` (non-string) | coerced to `"1"` | defaults to `v1` |
| `<<:` merge key inside a rule entry | treated as a literal dependency path | merged |
| Two YAML documents in one file | first document wins | `js-yaml` errors |
| Tab indentation | error, with the line number | error |
| Under-indented rule body | entry skipped, reported in `Policy.Warnings` | `'*'` applied with no settings, stray keys become separate entries |
| Aliases, duplicate keys, document-level merge | same | same |

The strictness is not obviously wrong — a user who writes garbage into `.snyk`
gets a diagnostic here and silence from the TypeScript parser — but it is a
difference, and picking a winner for each row is deliberately deferred.

## Known limitations

- **Key order is not preserved.** Rules are stored in maps, so `Load` followed by
  `Marshal` will reorder vulnerability IDs and dependency paths. The content
  round-trips; the layout does not.
- **Unreadable rules are not written back.** `Marshal` writes only what the
  policy holds, so a rule or field reported in `Policy.Warnings` is gone after a
  load and save, as unknown keys already are.
- **`failThreshold` is not validated.** Any string is accepted, not just the four
  `Severity` values.
- **The parser is partial.** It covers `ignore` and `patch`. There is no
  `suggest`, and no matching or filtering — `lib/filter` has no Go equivalent.

## Development

```bash
cd go
go test ./... -count=1
golangci-lint run
```

Tests read fixtures from two places: `dotsnyk/testdata/`, which came across with
the parser, and `../test/fixtures/`, the corpus the TypeScript implementation
uses. The second is why the parser lives here.

## Licence

[Apache-2.0](../LICENSE), the same as the rest of the repo and as the code it was
lifted from.
