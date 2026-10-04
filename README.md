# agent-evidence-admission

Admission policies that let a Kubernetes cluster admit or refuse a workload on its adversarial
execution evidence: a Rego oracle for OPA, Kyverno policies on the JMESPath and CEL rails, and
sigstore policy-controller policies.

It's for platform and security engineers who already run one of those engines and want a workload
to show what was tested against it before the cluster admits it, with a measured map of which
specification obligations each engine enforces.

## Quick start

Pin the policies to a commit and evaluate the sample statement with OPA:

```bash
git clone https://github.com/probityai/agent-evidence-admission && cd agent-evidence-admission
git checkout 1ded5b8d1ae4d13b8a2c3b61fc18f6a2d9d40119
opa eval -f raw -d rego/execution_evidence.rego \
  -I 'count(data.sigstore.errors)' < samples/adversarial-execution-evidence.pass.statement.json
```

It prints `3`: a deployment that has pinned nothing, and has not declared that it runs unpinned,
admits nothing. Pin the corpus, the substrate
and the classes you demand, and the policy admits the same statement:

```bash
cat > pins.json <<'JSON'
{"consumer": {
  "expected_corpus_digest": "cc1bdef2ffca96d86a636e5a9fb27a4a111836773e0dd1368d8de94f413979be",
  "expected_substrate_digest": "018bbaf3710e526b0653abafbd3bd3c3356150d747db166021f1e107446c85bb",
  "demanded_classes": ["XA"]
}}
JSON
opa eval -f raw -d rego/execution_evidence.rego -d pins.json \
  -I 'data.sigstore.isCompliant' < samples/adversarial-execution-evidence.pass.statement.json
```

It prints `true`. `opa test --timeout 120s rego/` runs the oracle's own test suite.

## Status

The policies follow the in-toto Adversarial Execution Evidence predicate v0.7, proposed in
[in-toto/attestation#570](https://github.com/in-toto/attestation/pull/570). The profile registry
measures them against the [agent-evidence-vectors](https://github.com/probityai/agent-evidence-vectors) corpus
at tag v0.10.1. The rails evaluate a statement whose envelope signature your engine's key
authority has already verified; they don't verify signatures themselves. Until you pin them, or
declare that you run unpinned, the policies refuse every statement that depends on a consumer
setting with no safe default.

## Documentation

| page | read it for |
| --- | --- |
| <a name="verify-the-claim-in-four-commands"></a><a name="what-is-here"></a><a name="why-the-rails-are-published"></a><a name="the-trust-ceiling-stated-before-you-rely-on-any-of-it"></a><a name="the-profile-registry"></a><a name="the-adversarial-ratchet"></a><a name="running-the-conformance-harness"></a><a name="continuous-integration"></a><a name="citation-and-provenance"></a>[Design, trust ceiling and evidence](https://github.com/probityai/agent-evidence-admission/blob/main/docs/DESIGN.md) | the file map, the trust ceiling, how each obligation's disposition is measured, and how to re-run the measurement |
| [Consumer policy](https://github.com/probityai/agent-evidence-admission/blob/main/docs/CONSUMER-POLICY.md) | the pins, what each one decides, and what an absent value means |
| [Model report gate](https://github.com/probityai/agent-evidence-admission/blob/main/consumers/policy-vocabulary/README.md) | install a selected reader, repeat the native report and enforce separate publication and quality decisions |
| [Pre-call budget](https://github.com/probityai/agent-evidence-admission/blob/main/consumers/spend-reservation/README.md) | reserve the maximum cost before dispatch and retain signed local effects |
| [Profile registry](https://github.com/probityai/agent-evidence-admission/blob/main/PROFILE-REGISTRY.md) | the enforced, approximated and unreachable obligations per rail |
| [Maturity model mapping](https://github.com/probityai/agent-evidence-admission/blob/main/docs/AUTOMATED-GOVERNANCE-MATURITY-MODEL.md) | each item of the CNCF Automated Governance Maturity Model and the file that serves it |
| [Adversarial ratchet](https://github.com/probityai/agent-evidence-admission/blob/main/docs/ADVERSARIAL-RATCHET.md) | the open adversarial-mutation findings against these rails |
| [Contributing](https://github.com/probityai/agent-evidence-admission/blob/main/CONTRIBUTING.md) and [provenance](https://github.com/probityai/agent-evidence-admission/blob/main/PROVENANCE.md) | how to propose a change, and where each policy file came from |

## License

Apache-2.0. Cite with [CITATION.cff](https://github.com/probityai/agent-evidence-admission/blob/main/CITATION.cff).
