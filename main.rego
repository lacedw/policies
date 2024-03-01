package policies.main

default allow = false

allow {
    input.path == ["record"]
    input.method == "POST"
}

caller_is_authorised[record] {
    record.user_id == input.user_id
}

caller_is_authorised[record] {
    some i; record.actor_ids[i] == input.actor_id
}

allow {
    input.path[_] == "record"
    input.method == "GET"
    record := get_record(input.id)
    caller_is_authorised[record]
}

get_record(id) = record {
    record := data.records[_]
    record.id = id
}