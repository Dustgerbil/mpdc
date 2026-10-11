# Schema 2 compatibility fixtures

`schema-v2-complete.json` and `schema-v2-minimal.json` were captured from the
unmodified source before the project-review improvements. The complete fixture
uses synthetic nonzero values to exercise every exported result field and nested
type; values such as `fixture` are structural sentinels, not scan conclusions.
The minimal fixture freezes required fields, null collections and omitted optional
fields. Both preserve the top-level array.

`TestSchemaV2LegacyFixtures` requires lossless decode/encode through the current
result types. Do not regenerate these baselines when adding optional fields.
