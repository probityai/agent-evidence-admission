# agent-evidence-admission

Checks that an artifact has the digest its document names: a TEA artifact, a CycloneDX SBOM or VEX, or an in-toto statement.

It is for manufacturers, integrators and admission controllers that receive a compliance document for a release and need to know the document covers the bytes they actually hold.

## Install

```bash
pip install agent-evidence-admission==0.1.0
```

## Example

```bash
uvx agent-evidence-admission==0.1.0 digest-check bom.json log4j-core-2.26.1.jar
```

The check runs three steps: read the document (a path or an https URL), recompute the artifact's digest with every algorithm the document names, and compare. It prints one line and exits 0 when a named digest matches:

```
PASS log4j-core-2.26.1.jar has sha512:..., named in bom.json
```

It exits 1 with `FAIL digest-mismatch` when the bytes differ, or `FAIL no-digest-named` when the document names no digest at all, and 2 when the document or the artifact could not be read. Plain http URLs are refused.

## Status

Version 0.1.0. The Kubernetes admission policies (Rego, Kyverno, policy-controller) live in the same repository; see the [repository README](https://github.com/probityai/agent-evidence-admission#readme).
