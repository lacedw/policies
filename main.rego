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
    record := data.records[_].id == input.id
    caller_is_authorised[record]
    input.path[_] == "record"
    input.method == "GET"
}