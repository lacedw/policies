package policies.main

default allow = false

get_record(id) = record {
    record := data.records[_]
    record.id == id
}

get_external_record(id) = record {
    response := http.send({
        "method": "get",
        "url": "https://raw.githubusercontent.com/lacedw/policies/master/external.json"
    })
    external_data := response.body
    record := external_data.records[_]
    record.id == id
}

caller_is_authorised {
    record := get_record(input.id)
    record.user_id == input.user_id
}

caller_is_authorised {
    record := get_record(input.id)
    some i; record.actor_ids[i] == input.actor_id
}

caller_is_authorised_external {
    record := get_external_record(input.id)
    some i; record.actor_ids[i] == input.actor_id
}

caller_is_authorised_external {
    record := get_external_record(input.id)
    record.user_id == input.user_id
}

external = false {
    input.path[_] == "external"
}

allow {
    input.path == ["record"]
    input.method == "POST"
}

allow {
    input.path[_] == "record"
    not external
    input.method == "GET"
    caller_is_authorised
}

allow {
    input.path[_] == "record"
    external
    input.method == "GET"
    caller_is_authorised_external
}