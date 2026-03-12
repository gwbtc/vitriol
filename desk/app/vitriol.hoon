::  /app/vitriol/hoon
::  Groundwire for GitHub — commit signing & on-chain identity verification
::
::  Two modes:
::    Signer (committer's ship):  POST /vitriol/sign
::    Verifier (CI's ship):       POST /vitriol/verify-commit
::
::  The signer signs commit content with the ship's Ed25519 networking
::  key — the same key attested on-chain via a Groundwire inscription.
::  The verifier checks the signature against the signer's on-chain
::  pass by scrying Jael (populated by ord-watcher).
::
/+  default-agent, server
|%
+$  card  card:agent:gall
+$  versioned-state
  $%  state-0
      state-1
  ==
+$  state-0
  $:  %0
      privkey=(unit @)
      pubkey=(unit @t)
      keys=(map @t [pubkey=@t name=@t added=@da])
  ==
+$  state-1
  $:  %1
      ~
  ==
::
++  to-hex
  |=  [width=@ val=@]
  ^-  @t
  =/  raw  (trip (scot %ux val))
  =/  clean  (skim (slag 2 raw) |=(c=@ !=(c '.')))
  =/  cur  (lent clean)
  ?:  (gte cur width)
    (crip (slag (sub cur width) clean))
  (crip (weld (reap (sub width cur) '0') clean))
::
++  from-hex
  |=  hex=@t
  ^-  @
  =/  chars  (flop (trip hex))
  =/  val=@  0
  =/  i=@  0
  |-
  ?~  chars  val
  =/  c  i.chars
  =/  nib=@
    ?:  &((gte c '0') (lte c '9'))  (sub c '0')
    ?:  &((gte c 'a') (lte c 'f'))  (add 10 (sub c 'a'))
    ?:  &((gte c 'A') (lte c 'F'))  (add 10 (sub c 'A'))
    !!
  $(chars t.chars, i +(i), val (add val (lsh [2 i] nib)))
--
^-  agent:gall
=|  state-1
=*  state  -
|_  =bowl:gall
+*  this  .
    def   ~(. (default-agent this %|) bowl)
::
++  on-init
  ^-  (quip card _this)
  :_  this
  :~  [%pass /eyre/connect %arvo %e %connect [~ /vitriol] dap.bowl]
  ==
::
++  on-save   !>(state)
::
++  on-load
  |=  =vase
  ^-  (quip card _this)
  =/  old  !<(versioned-state vase)
  ?-  -.old
    %1  `this(state old)
    %0  `this(state *state-1)
  ==
::
++  on-poke
  |=  [=mark =vase]
  ^-  (quip card _this)
  ?+  mark  (on-poke:def mark vase)
      %handle-http-request
    =/  [eyre-id=@ta req=inbound-request:eyre]
      !<([@ta inbound-request:eyre] vase)
    ?.  authenticated.req
      :_  this
      (give-simple-payload:app:server eyre-id [[403 ~] ~])
    =/  rl  (parse-request-line:server url.request.req)
    =/  meth  method.request.req
    ?+  site.rl
      :_  this
      (give-simple-payload:app:server eyre-id not-found:gen:server)
      ::
      ::  GET /vitriol/pubkey — return this ship's on-chain networking key
      ::
        [%vitriol %pubkey ~]
      =/  deed-result
        %-  mule  |.
        .^  [life=@ud pass=@ sec=(unit @)]
            %j
            /(scot %p our.bowl)/deed/(scot %da now.bowl)/(scot %p our.bowl)/1
        ==
      =/  result=json
        ?:  ?=(%| -.deed-result)
          (pairs:enjs:format ~[['configured' b+%.n] ['error' s+'no keys in Jael']])
        %-  pairs:enjs:format
        :~  ['configured' b+%.y]
            ['pass' s+(to-hex 130 pass.p.deed-result)]
            ['life' (numb:enjs:format life.p.deed-result)]
            ['ship' s+(scot %p our.bowl)]
        ==
      :_  this
      (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      ::
      ::  POST /vitriol/sign — sign commit content with networking key
      ::
        [%vitriol %sign ~]
      ?.  =(meth %'POST')
        =/  err=json  (pairs:enjs:format ['error' s+'POST required']~)
        :_  this
        (give-simple-payload:app:server eyre-id (json-response:gen:server err))
      ::  get our deed and ring from Jael
      =/  deed-result
        %-  mule  |.
        .^  [life=@ud pass=@ sec=(unit @)]
            %j
            /(scot %p our.bowl)/deed/(scot %da now.bowl)/(scot %p our.bowl)/1
        ==
      ?:  ?=(%| -.deed-result)
        =/  err=json  (pairs:enjs:format ['error' s+'no keys in Jael']~)
        :_  this
        (give-simple-payload:app:server eyre-id (json-response:gen:server err))
      =/  ring-result
        %-  mule  |.
        .^  @
            %j
            /(scot %p our.bowl)/vein/(scot %da now.bowl)/(scot %ud life.p.deed-result)
        ==
      ?:  ?=(%| -.ring-result)
        =/  err=json  (pairs:enjs:format ['error' s+'cannot read private key from Jael']~)
        :_  this
        (give-simple-payload:app:server eyre-id (json-response:gen:server err))
      ::  extract Ed25519 signing seed from ring
      ::  ring format (suite B): 1 byte 'B' + 32 bytes sgn-seed + 32 bytes cry-seed
      =/  sgn-seed  (end 8 (rsh 3 p.ring-result))
      =/  jon  (need (de:json:html q:(need body.request.req)))
      =/  content  (so:dejs:format (~(got by ((om:dejs:format same) jon)) 'content'))
      =/  msg=octs  [(met 3 content) content]
      =/  sig=@  (sign-octs:ed:crypto msg sgn-seed)
      =/  result=json
        %-  pairs:enjs:format
        :~  ['signature' s+(to-hex 128 sig)]
            ['signer_id' s+(scot %p our.bowl)]
            ['pass' s+(to-hex 130 pass.p.deed-result)]
        ==
      :_  this
      (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      ::
      ::  POST /vitriol/verify-commit — verify signature against on-chain key
      ::  Body: {"signer":"~ship", "signature":"hex...", "payload":"..."}
      ::
        [%vitriol %verify-commit ~]
      ?.  =(meth %'POST')
        =/  err=json  (pairs:enjs:format ['error' s+'POST required']~)
        :_  this
        (give-simple-payload:app:server eyre-id (json-response:gen:server err))
      =/  jon  (need (de:json:html q:(need body.request.req)))
      =/  fields  ((om:dejs:format same) jon)
      =/  signer-cord  (so:dejs:format (~(got by fields) 'signer'))
      =/  sig-hex      (so:dejs:format (~(got by fields) 'signature'))
      =/  payload       (so:dejs:format (~(got by fields) 'payload'))
      ::  resolve signer
      =/  who  (slav %p signer-cord)
      ::  scry Jael for signer's on-chain deed
      =/  deed-result
        %-  mule  |.
        .^  [life=@ud pass=@ sec=(unit @)]
            %j
            /(scot %p our.bowl)/deed/(scot %da now.bowl)/(scot %p who)/1
        ==
      ?:  ?=(%| -.deed-result)
        =/  result=json
          %-  pairs:enjs:format
          :~  ['verified' b+%.n]
              ['signer' s+signer-cord]
              ['error' s+'signer not found in Jael']
          ==
        :_  this
        (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      ?:  =(0 life.p.deed-result)
        =/  result=json
          %-  pairs:enjs:format
          :~  ['verified' b+%.n]
              ['signer' s+signer-cord]
              ['error' s+'signer has no keys (life=0)']
          ==
        :_  this
        (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      ::  extract Ed25519 signing pubkey from on-chain pass
      ::  pass format (suite b): 1 byte 'b' + 32 bytes sgn-pub + 32 bytes cry-pub
      =/  sgn-pub  (end 8 (rsh 3 pass.p.deed-result))
      =/  sig=@  (from-hex sig-hex)
      =/  msg=octs  [(met 3 payload) payload]
      =/  valid=?  (veri-octs:ed:crypto sig msg sgn-pub)
      =/  result=json
        ?:  valid
          %-  pairs:enjs:format
          :~  ['verified' b+%.y]
              ['signer' s+signer-cord]
              ['life' (numb:enjs:format life.p.deed-result)]
          ==
        %-  pairs:enjs:format
        :~  ['verified' b+%.n]
            ['signer' s+signer-cord]
            ['error' s+'signature does not match on-chain key']
        ==
      :_  this
      (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      ::
      ::  GET /vitriol/check-id/~ship — check if @p has on-chain Groundwire ID
      ::
        [%vitriol %check-id *]
      ?~  t.t.site.rl
        :_  this
        (give-simple-payload:app:server eyre-id not-found:gen:server)
      =/  who-knot=@t  i.t.t.site.rl
      =/  who  (slav %p who-knot)
      =/  deed
        %-  mule  |.
        .^  [life=@ud pass=@ sec=(unit @)]
            %j
            /(scot %p our.bowl)/deed/(scot %da now.bowl)/(scot %p who)/1
        ==
      =/  result=json
        ?:  ?=(%| -.deed)
          %-  pairs:enjs:format
          :~  ['attested' b+%.n]
              ['ship' s+who-knot]
              ['error' s+'ship not found in Jael']
          ==
        ?:  =(0 life.p.deed)
          %-  pairs:enjs:format
          :~  ['attested' b+%.n]
              ['ship' s+who-knot]
              ['error' s+'ship has no keys (life=0)']
          ==
        %-  pairs:enjs:format
        :~  ['attested' b+%.y]
            ['ship' s+who-knot]
            ['life' (numb:enjs:format life.p.deed)]
        ==
      :_  this
      (give-simple-payload:app:server eyre-id (json-response:gen:server result))
    ==
  ==
::
++  on-watch
  |=  =path
  ^-  (quip card _this)
  ?+  path  (on-watch:def path)
    [%http-response *]  `this
  ==
::
++  on-peek
  |=  =(pole knot)
  ^-  (unit (unit cage))
  ?+  pole  ~
      [%x %pubkey %json ~]
    =/  deed-result
      %-  mule  |.
      .^  [life=@ud pass=@ sec=(unit @)]
          %j
          /(scot %p our.bowl)/deed/(scot %da now.bowl)/(scot %p our.bowl)/1
      ==
    :-  ~  :-  ~  :-  %json
    !>  ^-  json
    ?:  ?=(%| -.deed-result)
      (pairs:enjs:format ['configured' b+%.n]~)
    %-  pairs:enjs:format
    :~  ['configured' b+%.y]
        ['pass' s+(to-hex 130 pass.p.deed-result)]
        ['life' (numb:enjs:format life.p.deed-result)]
    ==
  ==
::
++  on-agent  on-agent:def
++  on-leave  on-leave:def
++  on-arvo
  |=  [=wire =sign-arvo]
  ^-  (quip card _this)
  ?+  wire  (on-arvo:def wire sign-arvo)
    [%eyre *]  `this
  ==
++  on-fail   on-fail:def
--
