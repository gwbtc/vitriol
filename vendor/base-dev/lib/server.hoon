=,  eyre
|%
+$  request-line
  $:  [ext=(unit @ta) site=(list @t)]
      args=(list [key=@t value=@t])
  ==
++  parse-request-line
  |=  url=@t
  ^-  request-line
  (fall (rush url ;~(plug apat:de-purl:html yque:de-purl:html)) [[~ ~] ~])
++  json-to-octs
  |=  jon=json
  ^-  octs
  (as-octs:mimes:html (en:json:html jon))
++  app
  |%
  ++  give-simple-payload
    |=  [eyre-id=@ta =simple-payload:http]
    ^-  (list card:agent:gall)
    =/  header-cage
      [%http-response-header !>(response-header.simple-payload)]
    =/  data-cage
      [%http-response-data !>(data.simple-payload)]
    :~  [%give %fact ~[/http-response/[eyre-id]] header-cage]
        [%give %fact ~[/http-response/[eyre-id]] data-cage]
        [%give %kick ~[/http-response/[eyre-id]] ~]
    ==
  --
++  gen
  |%
  ++  json-response
    |=  =json
    ^-  simple-payload:http
    :_  `(json-to-octs json)
    [200 [['content-type' 'application/json'] ~]]
  ++  not-found
    ^-  simple-payload:http
    [[404 ~] ~]
  ++  bad-request
    |=  msg=@t
    ^-  simple-payload:http
    :_  `(as-octt:mimes:html (trip msg))
    [400 [['content-type' 'text/plain'] ~]]
  --
--
