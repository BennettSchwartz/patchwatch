# Advisory provenance

`osv.json` preserves the source records used for the historical package catalog. Each entry identifies its OSV endpoint and source timestamps. The records carry GitHub Advisory Database references and CVE aliases where available.

`cve.json` preserves CVE List records for the service advisories. Its `range_source` points to the vendor bulletin used to map the product's affected versions. Older CVE records frequently express those versions as prose, so the catalog records the reviewed mapping explicitly.

Source records retain their upstream attribution and licensing. Patchwatch's MIT license covers its code; consult the upstream projects for terms governing advisory data.

The runtime catalog contains the PyPI/npm projection of the OSV records. Other ecosystems present in the preserved source records can be added through explicit product mappings.
