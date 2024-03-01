package policies.main

default allow = false

allow {
    input.path == ["record"]
    input.method == "POST"
}

allow {
    some record in data.records
    record.id == input.id
    input.user_id == record.user_id
    input.method == "GET"
}