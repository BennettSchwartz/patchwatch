[← Patchwatch](../README.md)

# Advisory sources and services

Patchwatch combines package advisory matching with CVE-based prioritization.

| Source | Role |
| --- | --- |
| CVE List | Published vulnerability identity and vendor records; imports use an explicit product/version mapping. |
| GitHub Advisory Database | Imports reviewed package ranges and published fixes by GHSA identifier. |
| OSV | Looks up advisories for resolved package versions across 10 ecosystems, including historical releases. |
| CISA KEV | Identifies CVEs with documented exploitation and provides remediation guidance. |
| FIRST EPSS | Supplies a dated probability estimate and percentile for exploitation in the following 30 days. |

## Prioritize a scan

```sh
patchwatch scan --root ~/projects --osv --intelligence
```

Findings are ordered by KEV membership, then EPSS probability, with severity breaking ties. JSON reports retain feed timestamps and the CVE aliases used to join records. A missing score remains unknown. Feed errors produce coverage warnings and stop automatic updates for that run.

KEV membership establishes observed exploitation of the vulnerability. EPSS is a forecast. Applicability still comes from the product/version match and the vendor's affected-configuration guidance.

## Service inventory

Patchwatch checks versions of service binaries available on PATH: nginx, Apache HTTP Server, Redis, PostgreSQL, MySQL, and MariaDB. This reports the binary's version; an operator can confirm which instance is serving traffic. Catalog service identifiers are `nginx`, `httpd`, `redis`, `postgresql`, `mysql`, and `mariadb`.

For an observed version from another host or a service managed outside PATH:

```sh
patchwatch scan --root ./project --service httpd=2.4.49 --intelligence
```

Declared versions are labeled separately in the report. The bundled service rules cover historical nginx and Apache HTTP Server issues. Further service rules can be added with a CVE import. Distribution backports and vendor configuration requirements belong in the rule's instructions and deployment review.

## Import a package advisory

```sh
patchwatch catalog import --github GHSA-9wx4-h78v-vm56 --output ./catalog.json
```

The import reads GitHub Advisory Database directly. It validates the resulting entry and adds it to the output catalog, replacing an entry with the same identifier. Review changes before publishing the file.

## Import a service CVE

Use the vendor bulletin to specify the product mapping and affected range:

```sh
patchwatch catalog import --cve CVE-2021-41773 \
  --ecosystem Service --package httpd --versions '==2.4.49' \
  --fixed 2.4.51 --output ./catalog.json
```

This reads the published CVE List record. The explicit mapping accommodates CVE records with prose version descriptions or several products. The target 2.4.51 also addresses the follow-up Apache issue CVE-2021-42013.

## Historical catalog

The [advisory index](advisories.md) links each entry to its original record. Preserved source snapshots live in [catalog-sources](../catalog-sources/README.md). Entries distinguish exact malicious releases from continuous vulnerable ranges and retain each branch's published fix.

For package compromises, recovery guidance covers rebuilding the environment and credentials exposed during execution. Updating a dependency is one part of that recovery process.
