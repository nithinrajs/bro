signature sql-sig {
 ip-proto == tcp
 dst-port == 80
 http-request /.*(['])/
 event "Found SQLinjection!"
}
signature sql-sig3 {
 ip-proto == tcp
 dst-port == 80
 http-request-body /.*([^a-zA-Z0-9=&<>_])/
 event "Found sqlinjection in BODY!"
}