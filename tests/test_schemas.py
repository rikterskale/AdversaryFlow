from adversaryflow.pipeline.schemas import NODE_SCHEMAS


def test_all_twelve_nodes_have_structured_schemas() -> None:
    assert len(NODE_SCHEMAS) == 12
    assert set(NODE_SCHEMAS) == {
        "actor_identity",
        "attack_extraction",
        "advisory_extraction",
        "detection_extraction",
        "dossier_synthesis",
        "environment_fit",
        "roe_translation",
        "telemetry_mapping",
        "path_candidate_a",
        "path_candidate_b",
        "path_adjudication",
        "final_composition",
    }
    for schema in NODE_SCHEMAS.values():
        assert schema.model_json_schema()["type"] == "object"
