package policies.main

default allow = false

allow {
    input.path == ["record"]
    input.method == "POST"
}

record_ids contains record.id if {
    some record in data.records
}

caller_is_authorised[record] {
    record.id == input.id
    input.user_id == record.user_id
}

caller_is_authorised[record] {
    record.id == input.id
    record.actor_ids[_] == input.actor_id
}

allow {
    record := data.records[_].id == input.id
    caller_is_authorised
    input.method == "GET"
}