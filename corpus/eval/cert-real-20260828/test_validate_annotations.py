def _valid_annotation():
    return {
        "schema_version": 1,
        "document": "sample",
        "annotation_status": "PENDING_REVIEW",
        "entities": [
            {
                "id": "e1",
                "type": "malware",
                "value": "ExampleRat",
                "quote": "ExampleRat targets banks.",
                "page": 1,
            },
            {
                "id": "e2",
                "type": "sector",
                "value": "banks",
                "quote": "ExampleRat targets banks.",
                "page": 1,
            },
            {
                "id": "e3",
                "type": "indicator",
                "value": "evil.example",
                "source_value": "evil[.]example",
                "ioc_type": "domain",
                "quote": "IOC: evil[.]example",
                "page": 2,
            },
        ],
        "relationships": [
            {
                "source": "e1",
                "type": "targets",
                "target": "e2",
                "quote": "ExampleRat targets banks.",
                "page": 1,
            }
        ],
    }


def test_validate_accepts_grounded_entities_relationships_and_normalized_source_values():
    """Catches a validator that rejects canonical values despite preserving the literal source form."""
    from validate_annotations import validate

    annotation = _valid_annotation()
    pages = ["ExampleRat targets banks.", "IOC: evil[.]example"]
    errors = validate(annotation, "\n".join(pages), pages)

    assert errors == []


def test_validate_rejects_quote_missing_from_declared_page():
    """Catches citations that exist elsewhere in the document but carry a false page number."""
    from validate_annotations import validate

    annotation = _valid_annotation()
    annotation["entities"][0]["page"] = 2
    pages = ["ExampleRat targets banks.", "IOC: evil[.]example"]

    assert "entities[e1]: quote not found on page 2" in validate(
        annotation, "\n".join(pages), pages
    )


def test_validate_rejects_duplicate_entity_ids_and_dangling_relationships():
    """Catches ambiguous IDs and graph edges whose endpoints are not annotated."""
    from validate_annotations import validate

    annotation = _valid_annotation()
    annotation["entities"][1]["id"] = "e1"
    annotation["relationships"][0]["target"] = "missing"
    pages = ["ExampleRat targets banks.", "IOC: evil[.]example"]
    errors = validate(annotation, "\n".join(pages), pages)

    assert "duplicate entity id: e1" in errors
    assert "relationships[0]: unknown target missing" in errors


def test_validate_rejects_indicator_without_supported_ioc_type():
    """Catches reference items that the extractor cannot represent as indicators."""
    from validate_annotations import validate

    annotation = _valid_annotation()
    annotation["entities"][2]["ioc_type"] = "filename"
    pages = ["ExampleRat targets banks.", "IOC: evil[.]example"]

    assert "entities[e3]: unsupported ioc_type filename" in validate(
        annotation, "\n".join(pages), pages
    )
