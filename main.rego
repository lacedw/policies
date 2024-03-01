package policies.main

default allow = false

allow {
    input.path == ["record"]
    input.method == "POST"
}

user_is_authorized if {
    some i
    record := data.records[i]
    record.id == input.id
    input.user_id == record.user_id
}

allow {
    user_is_authorized
    input.method == "GET"
}