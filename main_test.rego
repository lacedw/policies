package policies.main

records :=  [
    {
        "id": "record:1",
        "user_id": "user:1",
        "actor_ids": ["practitioner:1", "organisation:1"]
    }
]

mock_get_external_record(id) := {
    "id": "record:2",
    "user_id": "user:2",
    "actor_ids": ["practitioner:2", "organisation:2"]
}

test_post_allowed {
	allow
        with input as {
            "id": "record:1",
            "actor_id": "practitioner:1",
            "path": ["record", 1],
            "method": "GET"
        }
        with data.records as records
}

test_post_not_allowed {
	not allow 
        with input as {
            "id": "record:1",
            "actor_id": "practitioner:2",
            "path": ["record", 1],
            "method": "GET"
        }
        with data.records as records
}


test_post_external_allowed {
	allow 
        with input as {
            "id": "record:2",
            "actor_id": "practitioner:2",
            "path": ["record", "external", 1],
            "method": "GET"
        }
}

test_post_external_not_allowed {
	not allow
        with input as {
            "id": "record:2",
            "actor_id": "practitioner:3",
            "path": ["record", "external", 1],
            "method": "GET"
        }
}

test_post_mocked_external_allowed {
	allow 
        with input as {
            "id": "record:2",
            "actor_id": "practitioner:2",
            "path": ["record", "external", 1],
            "method": "GET"
        }
        with get_external_record as mock_get_external_record
}

test_post_mocked_external_not_allowed {
	not allow
        with input as {
            "id": "record:2",
            "actor_id": "practitioner:3",
            "path": ["record", "external", 1],
            "method": "GET"
        }
        with get_external_record as mock_get_external_record
}