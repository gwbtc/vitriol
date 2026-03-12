::  /app/gwgh/hoon
::  Groundwire for GitHub — signing & verification agent
::
/-  gwgh
/+  default-agent, server, ecdsa
|%
+$  card  card:agent:gall
+$  versioned-state  state-0
+$  state-0
  $:  %0
      privkey=(unit @)
      pubkey=(unit @t)
      keys=(map @t gw-id:gwgh)
  ==
--
^-  agent:gall
=|  state-0
=*  state  -
|_  =bowl:gall
+*  this  .
    def   ~(. (default-agent this %|) bowl)
::
++  on-init
  ^-  (quip card _this)
  :_  this
  :~  [%pass /eyre/connect %arvo %e %connect [~ /gwgh] dap.bowl]
  ==
::
++  on-save   !>(state)
::
++  on-load
  |=  =vase
  ^-  (quip card _this)
  :-  ~
  this(state !<(versioned-state vase))
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
        [%gwgh %pubkey ~]
      =/  result=json
        ?~  pubkey
          (pairs:enjs:format ['configured' b+%.n]~)
        %-  pairs:enjs:format
        :~  ['configured' b+%.y]
            ['pubkey' s+u.pubkey]
            ['ship' s+(scot %p our.bowl)]
        ==
      :_  this
      (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      ::
        [%gwgh %sign ~]
      ?.  =(meth %'POST')
        =/  err=json  (pairs:enjs:format ['error' s+'POST required']~)
        :_  this
        (give-simple-payload:app:server eyre-id (json-response:gen:server err))
      ?~  privkey
        =/  err=json  (pairs:enjs:format ['error' s+'no signing key configured']~)
        :_  this
        (give-simple-payload:app:server eyre-id (json-response:gen:server err))
      =/  jon  (need (de:json:html q:(need body.request.req)))
      =/  content  (so:dejs:format (~(got by ((om:dejs:format same) jon)) 'content'))
      =/  msg-hash  (hash-cord:ecdsa content)
      =/  [v=@ r=@ s=@]  (sign:ecdsa msg-hash u.privkey)
      =/  result=json
        %-  pairs:enjs:format
        :~  ['signature' s+(sig-to-hex:ecdsa v r s)]
            ['signer_id' s+(scot %p our.bowl)]
            ['pubkey' s+(need pubkey)]
        ==
      :_  this
      (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      ::
        [%gwgh %verify *]
      ?~  t.t.site.rl
        :_  this
        (give-simple-payload:app:server eyre-id not-found:gen:server)
      =/  queried-key=@t  i.t.t.site.rl
      =/  found  (~(get by keys) queried-key)
      =/  result=json
        ?~  found
          (pairs:enjs:format ~[['verified' b+%.n] ['pubkey' s+queried-key]])
        %-  pairs:enjs:format
        :~  ['verified' b+%.y]
            ['pubkey' s+queried-key]
            ['name' s+name.u.found]
            ['added' s+(scot %da added.u.found)]
        ==
      :_  this
      (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      ::
        [%gwgh %keys ~]
      ?:  =(meth %'POST')
        =/  jon  (need (de:json:html q:(need body.request.req)))
        =/  fields  ((om:dejs:format same) jon)
        =/  pk  (so:dejs:format (~(got by fields) 'pubkey'))
        =/  nm  (so:dejs:format (~(got by fields) 'name'))
        =/  new-id=gw-id:gwgh  [pubkey=pk name=nm added=now.bowl]
        =/  result=json  (pairs:enjs:format ~[['ok' b+%.y] ['pubkey' s+pk] ['name' s+nm]])
        :_  this(keys (~(put by keys) pk new-id))
        (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      =/  result=json
        :-  %a
        %+  turn  ~(tap by keys)
        |=  [pk=@t =gw-id:gwgh]
        %-  pairs:enjs:format
        :~  ['pubkey' s+pk]
            ['name' s+name.gw-id]
            ['added' s+(scot %da added.gw-id)]
        ==
      :_  this
      (give-simple-payload:app:server eyre-id (json-response:gen:server result))
    ==
    ::
      %gwgh-action
    =/  act  !<(action:gwgh vase)
    ?-  -.act
        %generate-key
      =/  priv  (shax eny.bowl)
      =/  pub  (pubkey:ecdsa priv)
      =/  pub-hex  (point-to-hex:ecdsa pub)
      `this(privkey `priv, pubkey `pub-hex)
      ::
        %set-key
      =/  priv  (slav %ux privkey.act)
      =/  pub  (pubkey:ecdsa priv)
      =/  pub-hex  (point-to-hex:ecdsa pub)
      `this(privkey `priv, pubkey `pub-hex)
      ::
        %sign
      ?~  privkey  !!
      =/  msg-hash  (hash-cord:ecdsa content.act)
      =/  [v=@ r=@ s=@]  (sign:ecdsa msg-hash u.privkey)
      `this
      ::
        %add-key
      =/  new-id=gw-id:gwgh  [pubkey=pubkey.act name=name.act added=now.bowl]
      `this(keys (~(put by keys) pubkey.act new-id))
      ::
        %remove-key
      `this(keys (~(del by keys) pubkey.act))
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
      [%x %keys %json ~]
    :-  ~  :-  ~  :-  %json
    !>  ^-  json
    :-  %a
    %+  turn  ~(tap by keys)
    |=  [pk=@t =gw-id:gwgh]
    (pairs:enjs:format ~[['pubkey' s+pk] ['name' s+name.gw-id]])
    ::
      [%x %verify * %json ~]
    =/  qk=@t  (snag 2 `(list @t)`pole)
    :-  ~  :-  ~  :-  %json
    !>  ^-  json
    =/  found  (~(get by keys) qk)
    ?~  found
      (pairs:enjs:format ['verified' b+%.n]~)
    %-  pairs:enjs:format
    :~  ['verified' b+%.y]
        ['name' s+name.u.found]
    ==
    ::
      [%x %pubkey %json ~]
    :-  ~  :-  ~  :-  %json
    !>  ^-  json
    ?~  pubkey  (pairs:enjs:format ['configured' b+%.n]~)
    %-  pairs:enjs:format
    :~  ['configured' b+%.y]
        ['pubkey' s+u.pubkey]
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
