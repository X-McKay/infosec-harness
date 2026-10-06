"""Contract rules: definitive verdict admission."""





def test_definitive_support_requires_citations_cited_match_and_no_contrary():
    from infosec_harness.contracts import Citation, Evidence, Verdict, definitive_support

    def probe(identity, observed, **changes):
        return Evidence(
            id=identity,
            kind="probe",
            command="probe",
            exit_code=0,
            sandbox_id="probe",
            source_digest="digest",
            observations={
                "target_reached": True,
                "oracle_valid": True,
                "positive_control": True,
                "negative_control": True,
                "vulnerability_observed": observed,
                "workspace_digest": "workspace-digest",
                "source_verified": True,
                **changes,
            },
        )

    cited = [Citation(path="sink.py", start_line=1, end_line=1)]
    verdict = Verdict(label="potentially_exploitable", summary="s", evidence_ids=["a"])
    matching, contrary = probe("a", True), probe("b", False)
    incomplete = probe("c", False, negative_control=False)
    assert definitive_support(verdict, [matching]) == (False, [])
    verdict = verdict.model_copy(update={"citations": cited})
    assert definitive_support(verdict, [matching, incomplete]) == (True, [])
    assert definitive_support(verdict, [probe("z", True)]) == (False, [])
    assert definitive_support(verdict, [matching, contrary]) == (True, [contrary])
