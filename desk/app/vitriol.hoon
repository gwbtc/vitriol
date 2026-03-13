::  /app/vitriol/hoon
::  Groundwire for GitHub — commit signing, verification, and ecash payment
::
::  Roles:
::    Committer:   POST /vitriol/sign — signs commits with Ed25519 networking key
::    Maintainer:  POST /vitriol/verify-commit — verifies signatures against on-chain key
::
::  Signing uses the ship's Ed25519 networking key — the same key attested
::  on-chain via a Groundwire inscription. Verification checks the signature
::  against the signer's on-chain pass by scrying Jael (populated by
::  ord-watcher).
::
::  Ecash (optional):
::    Maintainers can set a sats-per-PR price. Committers configure a Cashu
::    mint and load sats via Lightning invoices. When signing, the agent
::    selects tokens from the wallet (>= required, <= 110%) and includes
::    them in the response. On verification, the maintainer NUT-03 swaps
::    the tokens at the mint to confirm their value before accepting.
::
::  Admin UI at /vitriol/admin (Sail). Landing page at /vitriol.
::  All endpoints require Eyre authentication.
::
/-  *vitriol
/+  default-agent, server, vitriol-ui, cashu
|%
+$  card  card:agent:gall
+$  versioned-state
  $%  state-0
      state-1
      state-2
      state-3
      state-4
      state-5
      state-6
      state-7
      state-8
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
+$  state-2
  $:  %2
      ecash-key=(unit [sec=@ pub=@])
  ==
+$  state-3
  $:  %3
      ecash-key=(unit [sec=@ pub=@])
      banned=(set @p)
  ==
+$  state-4
  $:  %4
      ecash-key=(unit [sec=@ pub=@])
      banned=(set @p)
      require-payment=?
  ==
+$  state-5
  $:  %5
      ecash-key=(unit [sec=@ pub=@])
      banned=(set @p)
      require-payment=?
      mint=(unit @t)
      wallet=(map @t (list cashu-proof))
      mint-keysets=(map @t (map @ud @t))
      pending-mints=(map @t pending-mint-quote)
  ==
+$  state-6
  $:  %6
      ecash-key=(unit [sec=@ pub=@])
      banned=(set @p)
      require-payment=?
      sats-per-pr=(unit @ud)
      mint=(unit @t)
      wallet=(map @t (list cashu-proof))
      mint-keysets=(map @t (map @ud @t))
      pending-mints=(map @t pending-mint-quote)
      pending-verifies=(map @t pending-verify)
  ==
+$  state-7
  $:  %7
      ecash-key=(unit [sec=@ pub=@])
      banned=(set @p)
      require-payment=?
      sats-per-pr=(unit @ud)
      mint=(unit @t)
      wallet=(map @t (list cashu-proof))
      mint-keysets=(map @t (map @ud @t))
      pending-mints=(map @t pending-mint-quote)
      pending-verifies=(map @t pending-verify)
      in-flight=(map @t [proofs=(list cashu-proof) mint=@t expiry=@da])
  ==
+$  state-8
  $:  %8
      ecash-key=(unit [sec=@ pub=@])
      banned=(set @p)
      require-payment=?
      sats-per-pr=(unit @ud)
      mint=(unit @t)
      wallet=(map @t (list cashu-proof))
      mint-keysets=(map @t (map @ud @t))
      pending-mints=(map @t pending-mint-quote)
      pending-verifies=(map @t pending-verify)
      in-flight=(map @t [proofs=(list cashu-proof) mint=@t expiry=@da])
      pending-melts=(map @t pending-melt)
  ==
::
++  ca  cashu
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
::
++  deed-safe
  |=  [=bowl:gall who=@p]
  ^-  (unit [life=@ud pass=@])
  =/  result=(each (unit point:jael) tang)
    %-  mule  |.
    .^  (unit point:jael)
        %j
        /(scot %p our.bowl)/pynt/(scot %da now.bowl)/(scot %p who)
    ==
  ?.  ?=(%& -.result)  ~
  ?~  p.result  ~
  =/  pnt  u.p.result
  ?:  =(0 life.pnt)  ~
  =/  ky  (~(get by keys.pnt) life.pnt)
  ?~  ky  ~
  `[life.pnt pass.u.ky]
::
++  ring-safe
  |=  [=bowl:gall lyf=@ud]
  ^-  (unit @)
  =/  result=(each * tang)
    %-  mule  |.
    .^  *
        %j
        /(scot %p our.bowl)/vein/(scot %da now.bowl)/(scot %ud lyf)
    ==
  ?.  ?=(%& -.result)  ~
  `;;(@ p.result)
++  gen-ecash-key
  |=  eny=@uvJ
  ^-  [sec=@ pub=@]
  =/  sec=@  (end [3 32] eny)
  =/  pub=@  (scalarmult-base:ed:crypto sec)
  [sec pub]
::
::
::  Authenticated encryption via Curve25519 ECDH.
::
::  Encrypt: ephemeral keypair → DH shared secret → derive enc_key
::  and mac_key → XOR plaintext with counter-mode keystream →
::  HMAC-SHA256 the ciphertext → return [eph-pub ciphertext mac].
::
::  Decrypt: DH shared secret → derive same keys → verify MAC →
::  XOR to recover plaintext.  Returns ~ on MAC failure.
::
++  ecash-encrypt
  |=  [plaintext=@ pt-len=@ud recipient-pub=@ eny=@]
  ^-  [eph-pub=@ ciphertext=@ ct-len=@ud mac=@]
  =/  eph-sec=@  (end [3 32] (shax eny))
  =/  eph-pub=@  (scalarmult-base:ed:crypto eph-sec)
  =/  shared=@  (shar:ed:crypto recipient-pub eph-sec)
  =/  enc-key=@  (shay 36 (cat 3 shared 'encrypt'))
  =/  mac-key=@  (shay 36 (cat 3 shared 'authenticate'))
  =/  keystream=@  (stream-bytes enc-key pt-len)
  =/  ct=@  (mix plaintext keystream)
  =/  mac=@  (shay (add 32 pt-len) (cat 3 mac-key ct))
  [eph-pub ct pt-len mac]
::
++  ecash-decrypt
  |=  [ciphertext=@ ct-len=@ud eph-pub=@ our-sec=@ mac=@]
  ^-  (unit @)
  =/  shared=@  (shar:ed:crypto eph-pub our-sec)
  =/  enc-key=@  (shay 36 (cat 3 shared 'encrypt'))
  =/  mac-key=@  (shay 36 (cat 3 shared 'authenticate'))
  ::  verify MAC before decrypting
  =/  expected-mac=@  (shay (add 32 ct-len) (cat 3 mac-key ciphertext))
  ?.  =(mac expected-mac)  ~
  =/  keystream=@  (stream-bytes enc-key ct-len)
  `(mix ciphertext keystream)
::
++  stream-bytes
  |=  [seed=@ n=@ud]
  ^-  @
  =/  blocks=@ud  (add (div n 32) ?:((gth (mod n 32) 0) 1 0))
  =/  out=@  0
  =/  i=@ud  0
  |-
  ?:  =(i blocks)
    (end [3 n] out)
  =/  block=@  (shay 36 (cat 3 seed i))
  $(i +(i), out (add (lsh [3 (mul 32 i)] block) out))
::
++  wallet-balance
  |=  w=(map @t (list cashu-proof))
  ^-  @ud
  %-  ~(rep by w)
  |=  [[mint=@t proofs=(list cashu-proof)] acc=@ud]
  (add acc (roll proofs |=([p=cashu-proof a=@ud] (add a amount.p))))
::
++  parse-form-field
  |=  [pairs=(list [@t @t]) field=@t]
  ^-  (unit @t)
  =/  matches  (skim pairs |=([k=@t *] =(k field)))
  ?~  matches  ~
  `+.i.matches
::
++  parse-ud
  |=  txt=@t
  ^-  (unit @ud)
  =/  chars  (trip txt)
  ?:  =(~ chars)  ~
  ?.  (levy chars |=(c=@ &((gte c '0') (lte c '9'))))
    ~
  `(roll chars |=([c=@ a=@ud] (add (mul a 10) (sub c '0'))))
::
++  parse-token-list
  |=  arr=(list json)
  ^-  (list cashu-proof)
  %+  murn  arr
  |=  t=json
  ^-  (unit cashu-proof)
  ?.  ?=([%o *] t)  ~
  =/  a  (~(get by p.t) 'amount')
  =/  i  (~(get by p.t) 'id')
  =/  s  (~(get by p.t) 'secret')
  =/  c  (~(get by p.t) 'C')
  ?~  a  ~
  ?~  i  ~
  ?~  s  ~
  ?~  c  ~
  =/  amt=@ud
    ?.  ?=([%n *] u.a)  0
    (roll (trip p.u.a) |=([ch=@ ac=@ud] (add (mul ac 10) (sub ch '0'))))
  ?.  ?=([%s *] u.i)  ~
  ?.  ?=([%s *] u.s)  ~
  ?.  ?=([%s *] u.c)  ~
  `[amt p.u.i p.u.s p.u.c]
::
::  Select proofs from wallet totaling >= required but <= 110% of required.
::  Returns (unit [selected remaining]) where selected are the proofs to spend
::  and remaining is the updated wallet.
::  Fails (returns ~) if no valid selection exists.
::
++  select-proofs
  |=  [w=(map @t (list cashu-proof)) required=@ud]
  ^-  (unit [selected=(list cashu-proof) remaining=(map @t (list cashu-proof))])
  =/  max=@ud  (div (mul required 11) 10)
  ::  flatten all proofs with their mint
  =/  all=(list [mint=@t proof=cashu-proof])
    %-  zing
    %+  turn  ~(tap by w)
    |=  [m=@t ps=(list cashu-proof)]
    (turn ps |=(p=cashu-proof [m p]))
  ::  sort by amount ascending for subset search
  =/  sorted=(list [mint=@t proof=cashu-proof])
    %+  sort  all
    |=  [a=[mint=@t proof=cashu-proof] b=[mint=@t proof=cashu-proof]]
    (lth amount.proof.a amount.proof.b)
  ::  find best valid subset via recursive search with pruning
  =/  found=(unit (list [mint=@t proof=cashu-proof]))
    =|  best=(unit (list [mint=@t proof=cashu-proof]))
    =|  current=(list [mint=@t proof=cashu-proof])
    =/  current-total=@ud  0
    |-  ^-  (unit (list [mint=@t proof=cashu-proof]))
    =/  in-range=?  &((gte current-total required) (lte current-total max))
    =/  better=?
      ?:  in-range
        ?|  ?=(~ best)
            %+  lth  current-total
            (roll (turn (need best) |=([m=@t p=cashu-proof] amount.p)) add)
        ==
      %.n
    =?  best  better  `current
    ?:  (gth current-total max)  best
    ?~  sorted  best
    =/  with
      %=  $
        sorted  t.sorted
        current  [i.sorted current]
        current-total  (add current-total amount.proof.i.sorted)
      ==
    %=  $
      sorted  t.sorted
      best  ?~(with best with)
    ==
  ?~  found  ~
  ::  build results: extract proofs and rebuild wallet
  =/  sel=(list cashu-proof)  (turn u.found |=([m=@t p=cashu-proof] p))
  =/  new-wallet=(map @t (list cashu-proof))  w
  =/  to-remove=(list [mint=@t proof=cashu-proof])  u.found
  |-  ^-  (unit [selected=(list cashu-proof) remaining=(map @t (list cashu-proof))])
  ?~  to-remove
    `[sel new-wallet]
  =/  m=@t  mint.i.to-remove
  =/  p=cashu-proof  proof.i.to-remove
  =/  existing=(list cashu-proof)  (~(gut by new-wallet) m ~)
  =/  updated=(list cashu-proof)
    %+  skip  existing
    |=  e=cashu-proof
    &(=(secret.e secret.p) =(amount.e amount.p))
  =.  new-wallet
    ?:  =(~ updated)
      (~(del by new-wallet) m)
    (~(put by new-wallet) m updated)
  $(to-remove t.to-remove)
--
^-  agent:gall
=|  state-8
=*  state  -
|_  =bowl:gall
+*  this  .
    def   ~(. (default-agent this %|) bowl)
::
++  on-init
  ^-  (quip card _this)
  =/  kp  (gen-ecash-key eny.bowl)
  :_  %=  this
        ecash-key       `kp
        banned          *(set @p)
        require-payment  %.n
        sats-per-pr     ~
        mint            ~
        wallet          *(map @t (list cashu-proof))
        mint-keysets    *(map @t (map @ud @t))
        pending-mints   *(map @t pending-mint-quote)
        pending-verifies  *(map @t pending-verify)
        in-flight       *(map @t [proofs=(list cashu-proof) mint=@t expiry=@da])
        pending-melts   *(map @t pending-melt)
      ==
  :~  [%pass /eyre/connect %arvo %e %connect [~ /vitriol] dap.bowl]
  ==
::
++  on-save   !>(state)
::
++  on-load
  |=  =vase
  ^-  (quip card _this)
  =/  old  !<(versioned-state vase)
  =/  eyre-card=card  [%pass /eyre/connect %arvo %e %connect [~ /vitriol] dap.bowl]
  =/  empty-wallet  *(map @t (list cashu-proof))
  =/  empty-keysets  *(map @t (map @ud @t))
  =/  empty-pending  *(map @t pending-mint-quote)
  =/  empty-verifies  *(map @t pending-verify)
  =/  empty-flights  *(map @t [proofs=(list cashu-proof) mint=@t expiry=@da])
  =/  empty-melts  *(map @t pending-melt)
  ?-  -.old
    %8  [~[eyre-card] this(state old)]
    %7
      :_  %=  this
            ecash-key       ecash-key.old
            banned          banned.old
            require-payment  require-payment.old
            sats-per-pr     sats-per-pr.old
            mint            mint.old
            wallet          wallet.old
            mint-keysets    mint-keysets.old
            pending-mints   pending-mints.old
            pending-verifies  pending-verifies.old
            in-flight       in-flight.old
            pending-melts   empty-melts
          ==
      ~[eyre-card]
    %6
      :_  %=  this
            ecash-key       ecash-key.old
            banned          banned.old
            require-payment  require-payment.old
            sats-per-pr     sats-per-pr.old
            mint            mint.old
            wallet          wallet.old
            mint-keysets    mint-keysets.old
            pending-mints   pending-mints.old
            pending-verifies  pending-verifies.old
            in-flight       empty-flights
            pending-melts   empty-melts
          ==
      ~[eyre-card]
    %5
      :_  %=  this
            ecash-key       ecash-key.old
            banned          banned.old
            require-payment  require-payment.old
            sats-per-pr     ~
            mint            mint.old
            wallet          wallet.old
            mint-keysets    mint-keysets.old
            pending-mints   pending-mints.old
            pending-verifies  empty-verifies
            in-flight       empty-flights
            pending-melts   empty-melts
          ==
      ~[eyre-card]
    %4
      :_  %=  this
            ecash-key       ecash-key.old
            banned          banned.old
            require-payment  require-payment.old
            sats-per-pr     ~
            mint            ~
            wallet          empty-wallet
            mint-keysets    empty-keysets
            pending-mints   empty-pending
            pending-verifies  empty-verifies
            in-flight       empty-flights
            pending-melts   empty-melts
          ==
      ~[eyre-card]
    %3
      :_  %=  this
            ecash-key       ecash-key.old
            banned          banned.old
            require-payment  %.n
            sats-per-pr     ~
            mint            ~
            wallet          empty-wallet
            mint-keysets    empty-keysets
            pending-mints   empty-pending
            pending-verifies  empty-verifies
            in-flight       empty-flights
            pending-melts   empty-melts
          ==
      ~[eyre-card]
    %2
      :_  %=  this
            ecash-key       ecash-key.old
            banned          *(set @p)
            require-payment  %.n
            sats-per-pr     ~
            mint            ~
            wallet          empty-wallet
            mint-keysets    empty-keysets
            pending-mints   empty-pending
            pending-verifies  empty-verifies
            in-flight       empty-flights
            pending-melts   empty-melts
          ==
      ~[eyre-card]
    %1
      =/  kp  (gen-ecash-key eny.bowl)
      :_  %=  this
            ecash-key       `kp
            banned          *(set @p)
            require-payment  %.n
            sats-per-pr     ~
            mint            ~
            wallet          empty-wallet
            mint-keysets    empty-keysets
            pending-mints   empty-pending
            pending-verifies  empty-verifies
            in-flight       empty-flights
            pending-melts   empty-melts
          ==
      ~[eyre-card]
    %0
      =/  kp  (gen-ecash-key eny.bowl)
      :_  %=  this
            ecash-key       `kp
            banned          *(set @p)
            require-payment  %.n
            sats-per-pr     ~
            mint            ~
            wallet          empty-wallet
            mint-keysets    empty-keysets
            pending-mints   empty-pending
            pending-verifies  empty-verifies
            in-flight       empty-flights
            pending-melts   empty-melts
          ==
      ~[eyre-card]
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
      ::  GET /vitriol — landing page
      ::
        [%vitriol ~]
      :_  this
      (html-response:vitriol-ui eyre-id (render-home:vitriol-ui our.bowl))
      ::
      ::  GET /vitriol/admin — admin UI
      ::
        [%vitriol %admin ~]
      :_  this
      %:  html-response:vitriol-ui
        eyre-id
        %:  render-admin:vitriol-ui
          our.bowl
          ecash-key
          banned
          require-payment
          sats-per-pr
          mint
          wallet
          pending-mints
          pending-melts
          to-hex
        ==
      ==
      ::
      ::  POST /vitriol/admin/ban — ban form action
      ::
        [%vitriol %admin %ban ~]
      ?.  =(meth %'POST')
        :_  this
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      =/  body=@t  (crip (trip q:(need body.request.req)))
      =/  pairs  (rush body yquy:de-purl:html)
      ?~  pairs
        :_  this
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      =/  ship-val  (parse-form-field u.pairs 'ship')
      ?~  ship-val
        :_  this
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      =/  who  (slaw %p u.ship-val)
      ?~  who
        :_  this
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      :_  this(banned (~(put in banned) u.who))
      (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      ::
      ::  POST /vitriol/admin/unban — unban form action
      ::
        [%vitriol %admin %unban ~]
      ?.  =(meth %'POST')
        :_  this
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      =/  body=@t  (crip (trip q:(need body.request.req)))
      =/  pairs  (rush body yquy:de-purl:html)
      ?~  pairs
        :_  this
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      =/  ship-val  (parse-form-field u.pairs 'ship')
      ?~  ship-val
        :_  this
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      =/  who  (slaw %p u.ship-val)
      ?~  who
        :_  this
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      :_  this(banned (~(del in banned) u.who))
      (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      ::
      ::  POST /vitriol/admin/toggle-payment — toggle require-payment
      ::
        [%vitriol %admin %toggle-payment ~]
      :_  this(require-payment !require-payment)
      (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      ::
      ::  POST /vitriol/admin/set-price — set sats per PR
      ::
        [%vitriol %admin %set-price ~]
      ?.  =(meth %'POST')
        :_  this
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      =/  body=@t  (crip (trip q:(need body.request.req)))
      =/  pairs  (rush body yquy:de-purl:html)
      ?~  pairs
        :_  this
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      =/  price-val  (parse-form-field u.pairs 'price')
      ?~  price-val
        :_  this(sats-per-pr ~)
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      ?:  =('' u.price-val)
        :_  this(sats-per-pr ~)
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      =/  price  (parse-ud u.price-val)
      ?~  price
        :_  this
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      :_  this(sats-per-pr ?:(=(0 u.price) ~ price))
      (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      ::
      ::  POST /vitriol/admin/withdraw — withdraw tokens to Lightning
      ::
        [%vitriol %admin %withdraw ~]
      ?.  =(meth %'POST')
        :_  this
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      =/  body=@t  (crip (trip q:(need body.request.req)))
      =/  pairs  (rush body yquy:de-purl:html)
      ?~  pairs
        :_  this
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      =/  mint-val  (parse-form-field u.pairs 'mint')
      =/  invoice-val  (parse-form-field u.pairs 'invoice')
      ?~  mint-val
        :_  this
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      ?~  invoice-val
        :_  this
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      ?:  |(=('' u.mint-val) =('' u.invoice-val))
        :_  this
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      =/  mint-clean=tape  (clean-mint-url:ca u.mint-val)
      =/  mint-cord=@t  (crip mint-clean)
      =/  proofs=(list cashu-proof)  (~(gut by wallet) mint-cord ~)
      ?:  =(~ proofs)
        :_  this
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      ::  request melt quote
      =/  nonce=@t  (scot %uv (sham [eny.bowl now.bowl 'melt']))
      =.  pending-melts
        %+  ~(put by pending-melts)  nonce
        [mint-cord %quote u.invoice-val ~ '' 0]
      =/  quote-body=@t  (en:json:html (build-melt-quote-request:ca u.invoice-val 'sat'))
      =/  quote-octs=octs  [(met 3 quote-body) quote-body]
      =/  quote-url=@t  (crip (weld mint-clean "/v1/melt/quote/bolt11"))
      =/  http-cards=(list card)
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      =/  iris-card=card
        [%pass /iris/melt/[nonce] %arvo %i %request [%'POST' quote-url ~[['content-type' 'application/json']] `quote-octs] *outbound-config:iris]
      :_  this
      (snoc http-cards iris-card)
      ::
      ::  POST /vitriol/admin/set-mint — set mint URL
      ::
        [%vitriol %admin %set-mint ~]
      ?.  =(meth %'POST')
        :_  this
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      =/  body=@t  (crip (trip q:(need body.request.req)))
      =/  pairs  (rush body yquy:de-purl:html)
      ?~  pairs
        :_  this
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      =/  mint-val  (parse-form-field u.pairs 'mint')
      ?~  mint-val
        :_  this(mint ~)
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      ?:  =('' u.mint-val)
        :_  this(mint ~)
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      :_  this(mint `(crip (clean-mint-url:ca u.mint-val)))
      (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      ::
      ::  POST /vitriol/admin/load-sats — request lightning invoice from mint
      ::
        [%vitriol %admin %load-sats ~]
      ?.  =(meth %'POST')
        :_  this
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      ?~  mint
        :_  this
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      =/  body=@t  (crip (trip q:(need body.request.req)))
      =/  pairs  (rush body yquy:de-purl:html)
      ?~  pairs
        :_  this
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      =/  amt-val  (parse-form-field u.pairs 'amount')
      ?~  amt-val
        :_  this
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      =/  amount  (parse-ud u.amt-val)
      ?~  amount
        :_  this
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      ?:  =(0 u.amount)
        :_  this
        (redirect-response:vitriol-ui eyre-id '/vitriol/admin')
      =/  mint-clean=tape  (clean-mint-url:ca u.mint)
      =/  mint-cord=@t  (crip mint-clean)
      ::  check for cached keyset
      =/  keyset-id=@t
        =/  ks  ~(tap by mint-keysets)
        ?~  ks  ''
        -.i.ks
      ::  generate nonce for this operation
      =/  nonce=@t  (scot %uv (sham [eny.bowl now.bowl]))
      =.  pending-mints
        %+  ~(put by pending-mints)  nonce
        :*  mint-cord
            ''
            ''
            u.amount
            keyset-id
            *@da
            ?:(=('' keyset-id) %fetch-keys %quote)
            *(list @t)
            *(list @)
        ==
      ?:  =('' keyset-id)
        ::  need to fetch keysets first
        =/  keys-url=@t  (crip (weld mint-clean "/v1/keysets"))
        :_  this
        :~  [%pass /iris/mint-keys/[nonce] %arvo %i %request [%'GET' keys-url ~ ~] *outbound-config:iris]
        ==
      ::  have keyset, go straight to quote
      =/  quote-body=@t  (en:json:html (build-mint-quote-request:ca u.amount 'sat'))
      =/  quote-octs=octs  [(met 3 quote-body) quote-body]
      =/  quote-url=@t  (crip (weld mint-clean "/v1/mint/quote/bolt11"))
      :_  this
      :~  [%pass /iris/mint-quote/[nonce] %arvo %i %request [%'POST' quote-url ~[['content-type' 'application/json']] `quote-octs] *outbound-config:iris]
      ==
      ::
      ::  GET /vitriol/pubkey — return this ship's on-chain networking key
      ::
        [%vitriol %pubkey ~]
      =/  deed  (deed-safe bowl our.bowl)
      =/  result=json
        ?~  deed
          (pairs:enjs:format ~[['configured' b+%.n] ['error' s+'no keys in Jael']])
        %-  pairs:enjs:format
        :~  ['configured' b+%.y]
            ['pass' s+(to-hex 130 pass.u.deed)]
            ['life' (numb:enjs:format life.u.deed)]
            ['ship' s+(scot %p our.bowl)]
        ==
      :_  this
      (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      ::
      ::  GET /vitriol/ecash-pubkey — return this ship's ecash encryption pubkey
      ::
        [%vitriol %ecash-pubkey ~]
      =/  result=json
        ?~  ecash-key
          (pairs:enjs:format ~[['configured' b+%.n] ['error' s+'ecash keypair not generated']])
        %-  pairs:enjs:format
        :~  ['configured' b+%.y]
            ['pubkey' s+(to-hex 64 pub.u.ecash-key)]
            ['ship' s+(scot %p our.bowl)]
        ==
      :_  this
      (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      ::
      ::  GET /vitriol/sats-per-pr — return the maintainer's price
      ::
        [%vitriol %sats-per-pr ~]
      =/  result=json
        ?~  sats-per-pr
          (pairs:enjs:format ~[['configured' b+%.n]])
        %-  pairs:enjs:format
        :~  ['configured' b+%.y]
            ['sats' (numb:enjs:format u.sats-per-pr)]
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
      =/  deed  (deed-safe bowl our.bowl)
      ?~  deed
        =/  err=json  (pairs:enjs:format ['error' s+'no keys in Jael']~)
        :_  this
        (give-simple-payload:app:server eyre-id (json-response:gen:server err))
      =/  ring  (ring-safe bowl life.u.deed)
      ?~  ring
        =/  err=json  (pairs:enjs:format ['error' s+'cannot read private key from Jael']~)
        :_  this
        (give-simple-payload:app:server eyre-id (json-response:gen:server err))
      =/  sgn-seed  (end 8 (rsh 3 u.ring))
      =/  jon  (need (de:json:html q:(need body.request.req)))
      =/  fields  ((om:dejs:format same) jon)
      =/  content  (so:dejs:format (~(got by fields) 'content'))
      =/  msg=octs  [(met 3 content) content]
      =/  sig=@  (sign-octs:ed:crypto msg sgn-seed)
      ::  check if ecash tokens are requested
      =/  sats-req=(unit @ud)
        =/  sr  (~(get by fields) 'sats_required')
        ?~  sr  ~
        ?.  ?=([%n *] u.sr)  ~
        =/  n=@ud  (roll (trip p.u.sr) |=([c=@ a=@ud] (add (mul a 10) (sub c '0'))))
        ?:(=(0 n) ~ `n)
      ?~  sats-req
        ::  no payment requested — plain signature
        =/  result=json
          %-  pairs:enjs:format
          :~  ['signature' s+(to-hex 128 sig)]
              ['signer_id' s+(scot %p our.bowl)]
              ['pass' s+(to-hex 130 pass.u.deed)]
          ==
        :_  this
        (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      ::  payment requested — select proofs from wallet
      =/  selection  (select-proofs wallet u.sats-req)
      ?~  selection
        =/  err=json
          %-  pairs:enjs:format
          :~  ['error' s+'insufficient wallet balance or no valid token selection within 110% of required']
              ['sats_required' (numb:enjs:format u.sats-req)]
              ['wallet_balance' (numb:enjs:format (wallet-balance wallet))]
          ==
        :_  this
        (give-simple-payload:app:server eyre-id (json-response:gen:server err))
      =/  selected=(list cashu-proof)  selected.u.selection
      =/  token-total=@ud  (roll selected |=([p=cashu-proof a=@ud] (add a amount.p)))
      ::  determine the source mint for selected tokens
      =/  token-mint=@t
        =/  mints  ~(tap by remaining.u.selection)
        ::  the mint that lost proofs is the source
        =/  orig-mints  ~(tap by wallet)
        =/  changed
          %+  skim  orig-mints
          |=  [m=@t ps=(list cashu-proof)]
          =/  new-ps  (~(gut by remaining.u.selection) m ~)
          !=(ps new-ps)
        ?~  changed  ?~(mints '' -.i.mints)
        -.i.changed
      ::  encrypt tokens if maintainer ecash pubkey provided
      =/  recipient-pub=(unit @)
        =/  rp  (~(get by fields) 'ecash_pubkey')
        ?~  rp  ~
        ?.  ?=([%s *] u.rp)  ~
        ?:  =('' p.u.rp)  ~
        `(from-hex p.u.rp)
      ::  build token payload — include mint URL in encrypted data
      =/  token-payload=@t
        %-  en:json:html
        %-  pairs:enjs:format
        :~  ['mint' s+token-mint]
            :-  'tokens'
            :-  %a
            %+  turn  selected
            |=  p=cashu-proof
            %-  pairs:enjs:format
            :~  ['amount' (numb:enjs:format amount.p)]
                ['id' s+id.p]
                ['secret' s+secret.p]
                ['C' s+c.p]
            ==
        ==
      ::  move tokens to in-flight with 30 minute TTL
      =/  flight-nonce=@t  (scot %uv (sham [eny.bowl now.bowl 'flight']))
      =/  flight-expiry=@da  (add now.bowl ~m30)
      =/  result=json
        ?~  recipient-pub
          ::  no pubkey — send tokens in plaintext (local use only)
          %-  pairs:enjs:format
          :~  ['signature' s+(to-hex 128 sig)]
              ['signer_id' s+(scot %p our.bowl)]
              ['pass' s+(to-hex 130 pass.u.deed)]
              ['ecash_tokens' s+token-payload]
              ['ecash_amount' (numb:enjs:format token-total)]
              ['ecash_encrypted' b+%.n]
          ==
        ::  encrypt with maintainer's pubkey (authenticated)
        =/  pt-len=@ud  (met 3 token-payload)
        =/  [eph-pub=@ ct=@ ct-len=@ud mac=@]
          (ecash-encrypt token-payload pt-len u.recipient-pub eny.bowl)
        %-  pairs:enjs:format
        :~  ['signature' s+(to-hex 128 sig)]
            ['signer_id' s+(scot %p our.bowl)]
            ['pass' s+(to-hex 130 pass.u.deed)]
            ['ecash_ciphertext' s+(to-hex (mul 2 ct-len) ct)]
            ['ecash_ephemeral_pubkey' s+(to-hex 64 eph-pub)]
            ['ecash_mac' s+(to-hex 64 mac)]
            ['ecash_amount' (numb:enjs:format token-total)]
            ['ecash_encrypted' b+%.y]
        ==
      =.  wallet  remaining.u.selection
      =.  in-flight  (~(put by in-flight) flight-nonce [selected token-mint flight-expiry])
      :_  this
      %+  weld
        (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      ^-  (list card)
      :~  [%pass /timer/in-flight/[flight-nonce] %arvo %b %wait flight-expiry]
      ==
      ::
      ::  POST /vitriol/verify-commit — verify signature against on-chain key
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
      =/  who-unit  (slaw %p signer-cord)
      ?~  who-unit
        =/  result=json
          %-  pairs:enjs:format
          :~  ['verified' b+%.n]
              ['signer' s+signer-cord]
              ['error' s+'invalid ship name']
          ==
        :_  this
        (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      =/  who  u.who-unit
      ?:  (~(has in banned) who)
        =/  result=json
          %-  pairs:enjs:format
          :~  ['verified' b+%.n]
              ['signer' s+signer-cord]
              ['error' s+'signer is banned']
          ==
        :_  this
        (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      =/  deed  (deed-safe bowl who)
      ?~  deed
        =/  result=json
          %-  pairs:enjs:format
          :~  ['verified' b+%.n]
              ['signer' s+signer-cord]
              ['error' s+'signer not found in Jael']
          ==
        :_  this
        (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      ?:  =(0 life.u.deed)
        =/  result=json
          %-  pairs:enjs:format
          :~  ['verified' b+%.n]
              ['signer' s+signer-cord]
              ['error' s+'signer has no keys (life=0)']
          ==
        :_  this
        (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      =/  sgn-pub  (end 8 (rsh 3 pass.u.deed))
      =/  sig=@  (from-hex sig-hex)
      =/  msg=octs  [(met 3 payload) payload]
      =/  valid=?  (veri-octs:ed:crypto sig msg sgn-pub)
      ?.  valid
        =/  result=json
          %-  pairs:enjs:format
          :~  ['verified' b+%.n]
              ['signer' s+signer-cord]
              ['error' s+'signature does not match on-chain key']
          ==
        :_  this
        (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      ::  signature valid — parse ecash tokens if present
      ::  tokens may be encrypted (ciphertext + ephemeral pubkey + mac) or plaintext
      =/  token-result=[tokens=(list cashu-proof) mint=@t]
        ::  try encrypted path first
        =/  ct-hex  (~(get by fields) 'ecash_ciphertext')
        =/  eph-hex  (~(get by fields) 'ecash_ephemeral_pubkey')
        =/  mac-hex  (~(get by fields) 'ecash_mac')
        ?:  &(?=(^ ct-hex) ?=(^ eph-hex) ?=(^ mac-hex) ?=([%s *] u.ct-hex) ?=([%s *] u.eph-hex) ?=([%s *] u.mac-hex))
          ::  decrypt using our ecash secret key
          ?~  ecash-key  [~ '']
          =/  ct=@  (from-hex p.u.ct-hex)
          =/  ct-len=@ud  (div (lent (trip p.u.ct-hex)) 2)
          =/  eph-pub=@  (from-hex p.u.eph-hex)
          =/  mac=@  (from-hex p.u.mac-hex)
          =/  plaintext  (ecash-decrypt ct ct-len eph-pub sec.u.ecash-key mac)
          ?~  plaintext  [~ '']
          =/  payload-json  (de:json:html u.plaintext)
          ?~  payload-json  [~ '']
          ?.  ?=([%o *] u.payload-json)  [~ '']
          ::  extract mint and tokens from decrypted payload
          =/  dec-mint=@t
            =/  m  (~(get by p.u.payload-json) 'mint')
            ?~  m  ''
            ?.  ?=([%s *] u.m)  ''
            p.u.m
          =/  dec-tokens
            =/  t  (~(get by p.u.payload-json) 'tokens')
            ?~  t  ~
            ?.  ?=([%a *] u.t)  ~
            (parse-token-list p.u.t)
          [dec-tokens dec-mint]
        ::  try plaintext path (backwards compat)
        =/  tok  (~(get by fields) 'ecash_tokens')
        =/  m-val=@t
          =/  m  (~(get by fields) 'mint')
          ?~  m  ''
          ?.  ?=([%s *] u.m)  ''
          p.u.m
        ?~  tok  [~ m-val]
        ?:  ?=([%s *] u.tok)
          =/  tok-json  (de:json:html p.u.tok)
          ?~  tok-json  [~ m-val]
          ::  could be {mint, tokens} object or bare array
          ?:  ?=([%o *] u.tok-json)
            =/  tm  (~(get by p.u.tok-json) 'mint')
            =/  tt  (~(get by p.u.tok-json) 'tokens')
            =/  dec-mint  ?~(tm m-val ?.(?=([%s *] u.tm) m-val p.u.tm))
            ?~  tt  [~ dec-mint]
            ?.  ?=([%a *] u.tt)  [~ dec-mint]
            [(parse-token-list p.u.tt) dec-mint]
          ?.  ?=([%a *] u.tok-json)  [~ m-val]
          [(parse-token-list p.u.tok-json) m-val]
        ?.  ?=([%a *] u.tok)  [~ m-val]
        [(parse-token-list p.u.tok) m-val]
      =/  incoming-tokens=(list cashu-proof)  tokens.token-result
      =/  token-total=@ud
        (roll incoming-tokens |=([p=cashu-proof a=@ud] (add a amount.p)))
      =/  mint-url-cord=@t  mint.token-result
      ::  check payment requirement
      ?:  &(require-payment ?=(^ sats-per-pr) (lth token-total u.sats-per-pr))
        =/  result=json
          %-  pairs:enjs:format
          :~  ['verified' b+%.n]
              ['signer' s+signer-cord]
              ['error' s+'insufficient ecash payment']
              ['sats_required' (numb:enjs:format u.sats-per-pr)]
              ['sats_received' (numb:enjs:format token-total)]
          ==
        :_  this
        (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      ::  no tokens — just return verified
      ?:  =(~ incoming-tokens)
        =/  result=json
          %-  pairs:enjs:format
          :~  ['verified' b+%.y]
              ['signer' s+signer-cord]
              ['life' (numb:enjs:format life.u.deed)]
          ==
        :_  this
        (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      ::  tokens present — NUT-03 swap to verify value before accepting
      ::  need mint URL to swap
      ?:  =('' mint-url-cord)
        =/  result=json
          %-  pairs:enjs:format
          :~  ['verified' b+%.n]
              ['signer' s+signer-cord]
              ['error' s+'ecash tokens included but no mint URL provided']
          ==
        :_  this
        (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      ::  get keyset id from first token
      =/  keyset-id=@t  id:(snag 0 incoming-tokens)
      =/  verify-id=@t  (scot %uv (sham [eny.bowl now.bowl 'verify']))
      =/  mint-clean=tape  (clean-mint-url:ca mint-url-cord)
      =.  pending-verifies
        %+  ~(put by pending-verifies)  verify-id
        :*  who
            life.u.deed
            (crip mint-clean)
            incoming-tokens
            token-total
            %fetch-keys
            keyset-id
            *(list @t)
            *(list @)
            %pending
            ''
        ==
      ::  fetch keyset keys for this keyset id
      =/  keys-url=@t  (crip ;:(weld mint-clean "/v1/keys/" (trip keyset-id)))
      =/  result=json
        %-  pairs:enjs:format
        :~  ['status' s+'pending']
            ['verify_id' s+verify-id]
            ['signer' s+signer-cord]
            ['message' s+'verifying ecash tokens via NUT-03 swap']
        ==
      =/  http-cards=(list card)
        (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      =/  iris-card=card
        [%pass /iris/verify-keys/[verify-id] %arvo %i %request [%'GET' keys-url ~ ~] *outbound-config:iris]
      :_  this
      (snoc http-cards iris-card)
      ::
      ::  GET /vitriol/verify-status/[id] — poll for swap verification result
      ::
        [%vitriol %verify-status *]
      ?~  t.t.site.rl
        :_  this
        (give-simple-payload:app:server eyre-id not-found:gen:server)
      =/  vid=@t  i.t.t.site.rl
      =/  pv  (~(get by pending-verifies) vid)
      ?~  pv
        =/  result=json
          (pairs:enjs:format ~[['error' s+'unknown verify_id']])
        :_  this
        (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      =/  result=json
        ?:  =(%pending result.u.pv)
          %-  pairs:enjs:format
          :~  ['status' s+'pending']
              ['verify_id' s+vid]
          ==
        ?:  =(%verified result.u.pv)
          %-  pairs:enjs:format
          :~  ['verified' b+%.y]
              ['signer' s+(scot %p signer.u.pv)]
              ['life' (numb:enjs:format life.u.pv)]
              ['ecash_received' (numb:enjs:format token-total.u.pv)]
          ==
        %-  pairs:enjs:format
        :~  ['verified' b+%.n]
            ['signer' s+(scot %p signer.u.pv)]
            ['error' s+error.u.pv]
        ==
      :_  this
      (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      ::
      ::  GET /vitriol/check-id/~ship
      ::
        [%vitriol %check-id *]
      ?~  t.t.site.rl
        :_  this
        (give-simple-payload:app:server eyre-id not-found:gen:server)
      =/  who-knot=@t  i.t.t.site.rl
      =/  who  (slav %p who-knot)
      =/  deed  (deed-safe bowl who)
      =/  result=json
        ?~  deed
          %-  pairs:enjs:format
          :~  ['attested' b+%.n]
              ['ship' s+who-knot]
              ['error' s+'ship not found in Jael']
          ==
        ?:  =(0 life.u.deed)
          %-  pairs:enjs:format
          :~  ['attested' b+%.n]
              ['ship' s+who-knot]
              ['error' s+'ship has no keys (life=0)']
          ==
        %-  pairs:enjs:format
        :~  ['attested' b+%.y]
            ['ship' s+who-knot]
            ['life' (numb:enjs:format life.u.deed)]
        ==
      :_  this
      (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      ::
      ::  POST /vitriol/ban — JSON API
      ::
        [%vitriol %ban ~]
      ?.  =(meth %'POST')
        =/  err=json  (pairs:enjs:format ['error' s+'POST required']~)
        :_  this
        (give-simple-payload:app:server eyre-id (json-response:gen:server err))
      =/  jon  (need (de:json:html q:(need body.request.req)))
      =/  ship-cord  (so:dejs:format (~(got by ((om:dejs:format same) jon)) 'ship'))
      =/  who  (slav %p ship-cord)
      =/  result=json
        %-  pairs:enjs:format
        :~  ['banned' b+%.y]
            ['ship' s+ship-cord]
        ==
      :_  this(banned (~(put in banned) who))
      (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      ::
      ::  POST /vitriol/unban — JSON API
      ::
        [%vitriol %unban ~]
      ?.  =(meth %'POST')
        =/  err=json  (pairs:enjs:format ['error' s+'POST required']~)
        :_  this
        (give-simple-payload:app:server eyre-id (json-response:gen:server err))
      =/  jon  (need (de:json:html q:(need body.request.req)))
      =/  ship-cord  (so:dejs:format (~(got by ((om:dejs:format same) jon)) 'ship'))
      =/  who  (slav %p ship-cord)
      =/  result=json
        %-  pairs:enjs:format
        :~  ['unbanned' b+%.y]
            ['ship' s+ship-cord]
        ==
      :_  this(banned (~(del in banned) who))
      (give-simple-payload:app:server eyre-id (json-response:gen:server result))
      ::
      ::  GET /vitriol/banned — list all banned ships
      ::
        [%vitriol %banned ~]
      =/  ships=(list @p)  ~(tap in banned)
      =/  result=json
        %-  pairs:enjs:format
        :~  ['count' (numb:enjs:format (lent ships))]
            :-  'ships'
            :-  %a
            (turn ships |=(s=@p s+(scot %p s)))
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
    =/  deed  (deed-safe bowl our.bowl)
    :-  ~  :-  ~  :-  %json
    !>  ^-  json
    ?~  deed
      (pairs:enjs:format ['configured' b+%.n]~)
    %-  pairs:enjs:format
    :~  ['configured' b+%.y]
        ['pass' s+(to-hex 130 pass.u.deed)]
        ['life' (numb:enjs:format life.u.deed)]
    ==
  ::
      [%x %ecash-pubkey %json ~]
    :-  ~  :-  ~  :-  %json
    !>  ^-  json
    ?~  ecash-key
      (pairs:enjs:format ['configured' b+%.n]~)
    %-  pairs:enjs:format
    :~  ['configured' b+%.y]
        ['pubkey' s+(to-hex 64 pub.u.ecash-key)]
        ['ship' s+(scot %p our.bowl)]
    ==
  ::
      [%x %banned %json ~]
    =/  ships=(list @p)  ~(tap in banned)
    :-  ~  :-  ~  :-  %json
    !>  ^-  json
    %-  pairs:enjs:format
    :~  ['count' (numb:enjs:format (lent ships))]
        :-  'ships'
        :-  %a
        (turn ships |=(s=@p s+(scot %p s)))
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
  ::
  ::  -- Mint flow: fetch keyset list --
  ::
      [%iris %mint-keys @ ~]
    =/  nonce=@t  i.t.t.wire
    =/  pending  (~(get by pending-mints) nonce)
    ?~  pending
      `this
    ?.  ?=([%iris %http-response *] sign-arvo)
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    =/  =client-response:iris  client-response.sign-arvo
    ?.  ?=([%finished *] client-response)  `this
    =/  response=response-header:http  response-header.client-response
    =/  body=(unit octs)  ?~(full-file.client-response ~ `data.u.full-file.client-response)
    ?.  =(200 status-code.response)
      ~&  >>>  [%mint-keys-rejected status-code.response]
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    ?~  body
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    =/  resp-json  (de:json:html q.u.body)
    ?~  resp-json
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    =/  jon  u.resp-json
    ?.  ?=([%o *] jon)
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    =/  ks  (~(get by p.jon) 'keysets')
    ?~  ks
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    ?.  ?=([%a *] u.ks)
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    ::  find first active keyset with unit=sat
    =/  matching=(list @t)
      %+  murn  p.u.ks
      |=  item=json
      ^-  (unit @t)
      ?.  ?=([%o *] item)  ~
      =/  active  (~(get by p.item) 'active')
      =/  unit-val  (~(get by p.item) 'unit')
      =/  id-val  (~(get by p.item) 'id')
      ?.  ?=([~ %b *] active)  ~
      ?.  =(%.y p.u.active)  ~
      ?.  ?=([~ %s *] unit-val)  ~
      ?.  =('sat' p.u.unit-val)  ~
      ?~  id-val  ~
      ?.  ?=([%s *] u.id-val)  ~
      (some p.u.id-val)
    =/  kid=@t  ?~(matching '' i.matching)
    ?:  =('' kid)
      ~&  >>>  %mint-no-active-keyset
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    ::  fetch keys for this keyset
    =.  pending-mints
      (~(put by pending-mints) nonce u.pending(keyset-id kid, step %keyset))
    =/  mint-clean=tape  (clean-mint-url:ca mint.u.pending)
    =/  keys-url=@t  (crip ;:(weld mint-clean "/v1/keys/" (trip kid)))
    :_  this
    :~  [%pass /iris/mint-keyset/[nonce] %arvo %i %request [%'GET' keys-url ~ ~] *outbound-config:iris]
    ==
  ::
  ::  -- Mint flow: fetch keyset keys --
  ::
      [%iris %mint-keyset @ ~]
    =/  nonce=@t  i.t.t.wire
    =/  pending  (~(get by pending-mints) nonce)
    ?~  pending  `this
    ?.  ?=([%iris %http-response *] sign-arvo)
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    =/  =client-response:iris  client-response.sign-arvo
    ?.  ?=([%finished *] client-response)  `this
    =/  response=response-header:http  response-header.client-response
    =/  body=(unit octs)  ?~(full-file.client-response ~ `data.u.full-file.client-response)
    ?.  =(200 status-code.response)
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    ?~  body
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    =/  resp-json  (de:json:html q.u.body)
    ?~  resp-json
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    =/  jon  u.resp-json
    ?.  ?=([%o *] jon)
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    =/  keys-val=(unit json)
      =/  ks  (~(get by p.jon) 'keysets')
      ?~  ks  (~(get by p.jon) 'keys')
      ?.  ?=([%a *] u.ks)  (~(get by p.jon) 'keys')
      ?~  p.u.ks  (~(get by p.jon) 'keys')
      =/  first  i.p.u.ks
      ?.  ?=([%o *] first)  (~(get by p.jon) 'keys')
      (~(get by p.first) 'keys')
    ?~  keys-val
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    ?.  ?=([%o *] u.keys-val)
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    =/  key-map=(map @ud @t)
      %-  ~(rep by p.u.keys-val)
      |=  [[amt-key=@t hex-val=json] acc=(map @ud @t)]
      ?.  ?=([%s *] hex-val)  acc
      =/  amt=@ud  (roll (trip amt-key) |=([c=@ a=@ud] (add (mul a 10) (sub c '0'))))
      ?:  =(0 amt)  acc
      (~(put by acc) amt p.hex-val)
    =.  mint-keysets  (~(put by mint-keysets) keyset-id.u.pending key-map)
    ::  now request mint quote
    =.  pending-mints
      (~(put by pending-mints) nonce u.pending(step %quote))
    =/  quote-body=@t  (en:json:html (build-mint-quote-request:ca amount.u.pending 'sat'))
    =/  quote-octs=octs  [(met 3 quote-body) quote-body]
    =/  mint-clean=tape  (clean-mint-url:ca mint.u.pending)
    =/  quote-url=@t  (crip (weld mint-clean "/v1/mint/quote/bolt11"))
    :_  this
    :~  [%pass /iris/mint-quote/[nonce] %arvo %i %request [%'POST' quote-url ~[['content-type' 'application/json']] `quote-octs] *outbound-config:iris]
    ==
  ::
  ::  -- Mint flow: receive quote with invoice --
  ::
      [%iris %mint-quote @ ~]
    =/  nonce=@t  i.t.t.wire
    =/  pending  (~(get by pending-mints) nonce)
    ?~  pending  `this
    ?.  ?=([%iris %http-response *] sign-arvo)
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    =/  =client-response:iris  client-response.sign-arvo
    ?.  ?=([%finished *] client-response)  `this
    =/  response=response-header:http  response-header.client-response
    =/  body=(unit octs)  ?~(full-file.client-response ~ `data.u.full-file.client-response)
    ?.  =(200 status-code.response)
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    ?~  body
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    =/  resp-json  (de:json:html q.u.body)
    ?~  resp-json
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    =/  quote-result  (parse-mint-quote:ca u.resp-json)
    ?~  quote-result
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    =/  expiry-da=@da  (add ~1970.1.1 (mul expiry.u.quote-result (bex 64)))
    =.  pending-mints
      %+  ~(put by pending-mints)  nonce
      u.pending(quote-id quote.u.quote-result, bolt11 request.u.quote-result, expiry expiry-da, step %check-quote)
    ::  start polling timer
    :_  this
    :~  [%pass /timer/mint/[nonce] %arvo %b %wait (add now.bowl ~s5)]
    ==
  ::
  ::  -- Mint flow: poll quote status --
  ::
      [%iris %mint-check @ ~]
    =/  nonce=@t  i.t.t.wire
    =/  pending  (~(get by pending-mints) nonce)
    ?~  pending  `this
    ?.  ?=([%iris %http-response *] sign-arvo)
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    =/  =client-response:iris  client-response.sign-arvo
    ?.  ?=([%finished *] client-response)  `this
    =/  response=response-header:http  response-header.client-response
    =/  body=(unit octs)  ?~(full-file.client-response ~ `data.u.full-file.client-response)
    ?.  =(200 status-code.response)
      :_  this
      :~  [%pass /timer/mint/[nonce] %arvo %b %wait (add now.bowl ~s5)]
      ==
    ?~  body
      :_  this
      :~  [%pass /timer/mint/[nonce] %arvo %b %wait (add now.bowl ~s5)]
      ==
    =/  resp-json  (de:json:html q.u.body)
    ?~  resp-json
      :_  this
      :~  [%pass /timer/mint/[nonce] %arvo %b %wait (add now.bowl ~s5)]
      ==
    =/  quote-result  (parse-mint-quote:ca u.resp-json)
    ?~  quote-result
      :_  this
      :~  [%pass /timer/mint/[nonce] %arvo %b %wait (add now.bowl ~s5)]
      ==
    ?:  =(state.u.quote-result 'PAID')
      ::  invoice paid — generate blinded outputs and mint tokens
      =/  amounts=(list @ud)  (split-amount:ca amount.u.pending)
      =/  idx=@ud  0
      =/  secrets=(list @t)  ~
      =/  bfactors=(list @)  ~
      =/  mint-outputs=(list [amount=@ud id=@t b-hex=@t])  ~
      |-  ^-  (quip card _this)
      ?:  (gte idx (lent amounts))
        ::  all outputs generated, send mint request
        =/  mint-req=json  (build-mint-request:ca quote-id.u.pending (flop mint-outputs))
        =/  mint-body=@t  (en:json:html mint-req)
        =/  mint-octs=octs  [(met 3 mint-body) mint-body]
        =/  mint-clean=tape  (clean-mint-url:ca mint.u.pending)
        =/  mint-url=@t  (crip (weld mint-clean "/v1/mint/bolt11"))
        =.  pending-mints
          (~(put by pending-mints) nonce u.pending(step %mint-tokens, secrets (flop secrets), blinding-factors (flop bfactors)))
        :_  this
        :~  [%pass /iris/mint-exec/[nonce] %arvo %i %request [%'POST' mint-url ~[['content-type' 'application/json']] `mint-octs] *outbound-config:iris]
        ==
      =/  amt=@ud  (snag idx amounts)
      =/  eny-seed=@  (sham [eny.bowl nonce idx now.bowl])
      =/  [b-hex=@t secret=@t blinding-factor=@]  (make-output:ca amt keyset-id.u.pending eny-seed)
      %=  $
        idx  +(idx)
        secrets  [secret secrets]
        bfactors  [blinding-factor bfactors]
        mint-outputs  [[amt keyset-id.u.pending b-hex] mint-outputs]
      ==
    ::  not paid yet — schedule another check
    :_  this
    :~  [%pass /timer/mint/[nonce] %arvo %b %wait (add now.bowl ~s5)]
    ==
  ::
  ::  -- Mint flow: receive minted tokens --
  ::
      [%iris %mint-exec @ ~]
    =/  nonce=@t  i.t.t.wire
    =/  pending  (~(get by pending-mints) nonce)
    ?~  pending  `this
    ?.  ?=([%iris %http-response *] sign-arvo)
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    =/  =client-response:iris  client-response.sign-arvo
    ?.  ?=([%finished *] client-response)  `this
    =/  response=response-header:http  response-header.client-response
    =/  body=(unit octs)  ?~(full-file.client-response ~ `data.u.full-file.client-response)
    ?.  =(200 status-code.response)
      ~&  >>>  [%mint-exec-rejected status-code.response]
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    ?~  body
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    =/  resp-json  (de:json:html q.u.body)
    ?~  resp-json
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    ::  parse signatures and unblind
    =/  sigs  (parse-swap-response:ca u.resp-json)
    =/  key-map=(map @ud @t)  (~(gut by mint-keysets) keyset-id.u.pending *(map @ud @t))
    =/  mint-keys=(map @ud [x=@ y=@])
      %-  ~(run by key-map)
      |=  hex=@t
      =/  result  (mule |.((hex-to-point:ca hex)))
      ?:(?=([%& *] result) p.result [0 0])
    =/  new-proofs=(list cashu-proof)
      %:  finalize-proofs:ca
        sigs
        secrets.u.pending
        blinding-factors.u.pending
        mint-keys
      ==
    ::  add proofs to wallet
    =/  existing-proofs=(list cashu-proof)  (~(gut by wallet) mint.u.pending ~)
    =.  wallet  (~(put by wallet) mint.u.pending (weld existing-proofs new-proofs))
    =.  pending-mints  (~(del by pending-mints) nonce)
    ~&  >  [%mint-success (lent new-proofs) %proofs]
    `this
  ::
  ::  -- Mint flow: timer fires to poll --
  ::
      [%timer %mint @ ~]
    =/  nonce=@t  i.t.t.wire
    =/  pending  (~(get by pending-mints) nonce)
    ?~  pending  `this
    ?.  ?=([%behn %wake *] sign-arvo)  `this
    ::  check if expired
    ?:  &(!=(expiry.u.pending *@da) (gth now.bowl expiry.u.pending))
      ~&  >>>  %mint-quote-expired
      =.  pending-mints  (~(del by pending-mints) nonce)
      `this
    ::  poll quote status
    =/  mint-clean=tape  (clean-mint-url:ca mint.u.pending)
    =/  check-url=@t  (crip ;:(weld mint-clean "/v1/mint/quote/bolt11/" (trip quote-id.u.pending)))
    :_  this
    :~  [%pass /iris/mint-check/[nonce] %arvo %i %request [%'GET' check-url ~ ~] *outbound-config:iris]
    ==
  ::
  ::  -- In-flight token recovery: NUT-03 swap after 30 min TTL --
  ::
      [%timer %in-flight @ ~]
    =/  fid=@t  i.t.t.wire
    =/  flight  (~(get by in-flight) fid)
    ?~  flight  `this
    ?.  ?=([%behn %wake *] sign-arvo)  `this
    ::  TTL expired — swap these tokens at the mint for fresh ones
    =/  flight-mint=@t  mint.u.flight
    ?:  =('' flight-mint)
      ::  no mint URL — just return tokens to wallet as-is
      =/  existing=(list cashu-proof)  (~(gut by wallet) flight-mint ~)
      =.  wallet  (~(put by wallet) flight-mint (weld existing proofs.u.flight))
      =.  in-flight  (~(del by in-flight) fid)
      `this
    ::  get keyset id from first token
    =/  keyset-id=@t  id:(snag 0 proofs.u.flight)
    ::  check if we have cached keys for this keyset
    =/  cached-keys  (~(get by mint-keysets) keyset-id)
    =/  mint-clean=tape  (clean-mint-url:ca flight-mint)
    ?~  cached-keys
      ::  need to fetch keys first — reuse verify-keys flow
      ::  store as a pending-verify with the in-flight tokens
      =.  pending-verifies
        %+  ~(put by pending-verifies)  fid
        :*  our.bowl
            0
            flight-mint
            proofs.u.flight
            (roll proofs.u.flight |=([p=cashu-proof a=@ud] (add a amount.p)))
            %fetch-keys
            keyset-id
            *(list @t)
            *(list @)
            %pending
            ''
        ==
      =.  in-flight  (~(del by in-flight) fid)
      =/  keys-url=@t  (crip ;:(weld mint-clean "/v1/keys/" (trip keyset-id)))
      :_  this
      :~  [%pass /iris/verify-keys/[fid] %arvo %i %request [%'GET' keys-url ~ ~] *outbound-config:iris]
      ==
    ::  have keys — build swap directly
    =.  pending-verifies
      %+  ~(put by pending-verifies)  fid
      :*  our.bowl
          0
          flight-mint
          proofs.u.flight
          (roll proofs.u.flight |=([p=cashu-proof a=@ud] (add a amount.p)))
          %fetch-keys
          keyset-id
          *(list @t)
          *(list @)
          %pending
          ''
      ==
    =.  in-flight  (~(del by in-flight) fid)
    =/  keys-url=@t  (crip ;:(weld mint-clean "/v1/keys/" (trip keyset-id)))
    :_  this
    :~  [%pass /iris/verify-keys/[fid] %arvo %i %request [%'GET' keys-url ~ ~] *outbound-config:iris]
    ==
  ::
  ::  -- Verify flow: fetch keyset keys for swap --
  ::
      [%iris %verify-keys @ ~]
    =/  vid=@t  i.t.t.wire
    =/  pv  (~(get by pending-verifies) vid)
    ?~  pv  `this
    ?.  ?=([%iris %http-response *] sign-arvo)
      =.  pending-verifies
        (~(put by pending-verifies) vid u.pv(result %failed, error 'keyset fetch failed'))
      `this
    =/  =client-response:iris  client-response.sign-arvo
    ?.  ?=([%finished *] client-response)  `this
    =/  response=response-header:http  response-header.client-response
    =/  body=(unit octs)  ?~(full-file.client-response ~ `data.u.full-file.client-response)
    ?.  =(200 status-code.response)
      =.  pending-verifies
        (~(put by pending-verifies) vid u.pv(result %failed, error 'mint keyset request rejected'))
      `this
    ?~  body
      =.  pending-verifies
        (~(put by pending-verifies) vid u.pv(result %failed, error 'empty keyset response'))
      `this
    =/  resp-json  (de:json:html q.u.body)
    ?~  resp-json
      =.  pending-verifies
        (~(put by pending-verifies) vid u.pv(result %failed, error 'invalid keyset json'))
      `this
    ::  parse keys — try both /v1/keys/{id} and /v1/keysets formats
    =/  jon  u.resp-json
    ?.  ?=([%o *] jon)
      =.  pending-verifies
        (~(put by pending-verifies) vid u.pv(result %failed, error 'keyset not an object'))
      `this
    =/  keys-val=(unit json)
      =/  ks  (~(get by p.jon) 'keysets')
      ?~  ks  (~(get by p.jon) 'keys')
      ?.  ?=([%a *] u.ks)  (~(get by p.jon) 'keys')
      ?~  p.u.ks  (~(get by p.jon) 'keys')
      =/  first  i.p.u.ks
      ?.  ?=([%o *] first)  (~(get by p.jon) 'keys')
      (~(get by p.first) 'keys')
    ?~  keys-val
      =.  pending-verifies
        (~(put by pending-verifies) vid u.pv(result %failed, error 'no keys in response'))
      `this
    ?.  ?=([%o *] u.keys-val)
      =.  pending-verifies
        (~(put by pending-verifies) vid u.pv(result %failed, error 'keys not an object'))
      `this
    =/  key-map=(map @ud @t)
      %-  ~(rep by p.u.keys-val)
      |=  [[amt-key=@t hex-val=json] acc=(map @ud @t)]
      ?.  ?=([%s *] hex-val)  acc
      =/  amt=@ud  (roll (trip amt-key) |=([c=@ a=@ud] (add (mul a 10) (sub c '0'))))
      ?:  =(0 amt)  acc
      (~(put by acc) amt p.hex-val)
    =.  mint-keysets  (~(put by mint-keysets) keyset-id.u.pv key-map)
    ::  build swap request: create fresh outputs for each input proof
    =/  amounts=(list @ud)  (turn tokens.u.pv |=(p=cashu-proof amount.p))
    =/  idx=@ud  0
    =/  secrets=(list @t)  ~
    =/  bfactors=(list @)  ~
    =/  outputs=(list [amount=@ud id=@t b-hex=@t])  ~
    |-  ^-  (quip card _this)
    ?:  (gte idx (lent amounts))
      ::  build swap JSON
      =/  inputs-json=json
        :-  %a
        %+  turn  tokens.u.pv
        |=  p=cashu-proof
        %-  pairs:enjs:format
        :~  ['amount' (numb:enjs:format amount.p)]
            ['id' s+id.p]
            ['secret' s+secret.p]
            ['C' s+c.p]
        ==
      =/  swap-req=json
        (build-swap-request:ca inputs-json (flop outputs))
      =/  swap-body=@t  (en:json:html swap-req)
      =/  swap-octs=octs  [(met 3 swap-body) swap-body]
      =/  mint-clean=tape  (clean-mint-url:ca mint.u.pv)
      =/  swap-url=@t  (crip (weld mint-clean "/v1/swap"))
      =.  pending-verifies
        %+  ~(put by pending-verifies)  vid
        u.pv(step %swap, secrets (flop secrets), blinding-factors (flop bfactors))
      :_  this
      :~  [%pass /iris/verify-swap/[vid] %arvo %i %request [%'POST' swap-url ~[['content-type' 'application/json']] `swap-octs] *outbound-config:iris]
      ==
    =/  amt=@ud  (snag idx amounts)
    =/  eny-seed=@  (sham [eny.bowl vid idx now.bowl])
    =/  [b-hex=@t secret=@t blinding-factor=@]  (make-output:ca amt keyset-id.u.pv eny-seed)
    %=  $
      idx  +(idx)
      secrets  [secret secrets]
      bfactors  [blinding-factor bfactors]
      outputs  [[amt keyset-id.u.pv b-hex] outputs]
    ==
  ::
  ::  -- Verify flow: receive swap result --
  ::
      [%iris %verify-swap @ ~]
    =/  vid=@t  i.t.t.wire
    =/  pv  (~(get by pending-verifies) vid)
    ?~  pv  `this
    ?.  ?=([%iris %http-response *] sign-arvo)
      =.  pending-verifies
        (~(put by pending-verifies) vid u.pv(result %failed, error 'swap request failed'))
      `this
    =/  =client-response:iris  client-response.sign-arvo
    ?.  ?=([%finished *] client-response)  `this
    =/  response=response-header:http  response-header.client-response
    =/  body=(unit octs)  ?~(full-file.client-response ~ `data.u.full-file.client-response)
    ?.  =(200 status-code.response)
      =/  err-body=@t
        ?~  body  'no body'
        (crip (scag 200 (trip q.u.body)))
      =.  pending-verifies
        (~(put by pending-verifies) vid u.pv(result %failed, error (crip ;:(weld "swap rejected: " (trip err-body)))))
      `this
    ?~  body
      =.  pending-verifies
        (~(put by pending-verifies) vid u.pv(result %failed, error 'empty swap response'))
      `this
    =/  resp-json  (de:json:html q.u.body)
    ?~  resp-json
      =.  pending-verifies
        (~(put by pending-verifies) vid u.pv(result %failed, error 'invalid swap json'))
      `this
    ::  parse signatures and unblind
    =/  sigs  (parse-swap-response:ca u.resp-json)
    =/  key-map=(map @ud @t)  (~(gut by mint-keysets) keyset-id.u.pv *(map @ud @t))
    =/  mint-keys=(map @ud [x=@ y=@])
      %-  ~(run by key-map)
      |=  hex=@t
      =/  result  (mule |.((hex-to-point:ca hex)))
      ?:(?=([%& *] result) p.result [0 0])
    =/  new-proofs=(list cashu-proof)
      %:  finalize-proofs:ca
        sigs
        secrets.u.pv
        blinding-factors.u.pv
        mint-keys
      ==
    ::  swap succeeded — tokens are real, store them in wallet
    =/  existing=(list cashu-proof)  (~(gut by wallet) mint.u.pv ~)
    =.  wallet  (~(put by wallet) mint.u.pv (weld existing new-proofs))
    =.  pending-verifies
      (~(put by pending-verifies) vid u.pv(result %verified))
    ~&  >  [%verify-swap-success (lent new-proofs) %proofs token-total.u.pv %sats]
    `this
  ::
  ::  -- Melt flow: withdraw tokens to Lightning --
  ::
      [%iris %melt @ ~]
    =/  nonce=@t  i.t.t.wire
    =/  pm  (~(get by pending-melts) nonce)
    ?~  pm  `this
    ?.  ?=([%iris %http-response *] sign-arvo)
      ::  restore proofs on failure if we were in execute step
      ?.  =(%execute step.u.pm)
        =.  pending-melts  (~(del by pending-melts) nonce)
        `this
      =/  existing=(list cashu-proof)  (~(gut by wallet) mint.u.pm ~)
      =.  wallet  (~(put by wallet) mint.u.pm (weld existing proofs-used.u.pm))
      =.  pending-melts  (~(del by pending-melts) nonce)
      `this
    =/  =client-response:iris  client-response.sign-arvo
    ?.  ?=([%finished *] client-response)  `this
    =/  response=response-header:http  response-header.client-response
    =/  body=(unit octs)  ?~(full-file.client-response ~ `data.u.full-file.client-response)
    ?.  =(200 status-code.response)
      ~&  >>>  [%melt-rejected status-code.response]
      ::  restore proofs if in execute step
      ?.  =(%execute step.u.pm)
        =.  pending-melts  (~(del by pending-melts) nonce)
        `this
      =/  existing=(list cashu-proof)  (~(gut by wallet) mint.u.pm ~)
      =.  wallet  (~(put by wallet) mint.u.pm (weld existing proofs-used.u.pm))
      =.  pending-melts  (~(del by pending-melts) nonce)
      `this
    ?~  body
      =.  pending-melts  (~(del by pending-melts) nonce)
      `this
    =/  resp-json  (de:json:html q.u.body)
    ?~  resp-json
      =.  pending-melts  (~(del by pending-melts) nonce)
      `this
    =/  jon  u.resp-json
    ?-  step.u.pm
        %quote
      ::  parse melt quote and select proofs
      =/  quote-result  (parse-melt-quote:ca jon)
      ?~  quote-result
        ~&  >>>  %melt-bad-quote
        =.  pending-melts  (~(del by pending-melts) nonce)
        `this
      =/  [quote-id=@t quote-amt=@ud fee-res=@ud]  u.quote-result
      =/  needed=@ud  (add quote-amt fee-res)
      =/  all-proofs=(list cashu-proof)  (~(gut by wallet) mint.u.pm ~)
      ::  select proofs greedily until we cover needed amount
      =/  selected=(list cashu-proof)  ~
      =/  remaining=(list cashu-proof)  ~
      =/  selected-total=@ud  0
      =/  to-scan=(list cashu-proof)  all-proofs
      |-  ^-  (quip card _this)
      ?:  (gte selected-total needed)
        ::  have enough — execute melt
        =.  remaining  (weld remaining to-scan)
        =/  melt-body=@t
          %-  en:json:html
          %+  build-melt-request:ca  quote-id
          %+  turn  selected
          |=(p=cashu-proof [amount.p id.p secret.p c.p])
        =/  melt-octs=octs  [(met 3 melt-body) melt-body]
        =/  mint-clean=tape  (clean-mint-url:ca mint.u.pm)
        =/  melt-url=@t  (crip (weld mint-clean "/v1/melt/bolt11"))
        =.  pending-melts
          (~(put by pending-melts) nonce u.pm(step %execute, proofs-used selected, quote-id quote-id, fee-reserve fee-res))
        =.  wallet  (~(put by wallet) mint.u.pm remaining)
        :_  this
        :~  [%pass /iris/melt/[nonce] %arvo %i %request [%'POST' melt-url ~[['content-type' 'application/json']] `melt-octs] *outbound-config:iris]
        ==
      ?~  to-scan
        ::  not enough proofs
        ~&  >>>  [%melt-insufficient-funds needed selected-total]
        =.  pending-melts  (~(del by pending-melts) nonce)
        `this
      %=  $
        selected  [i.to-scan selected]
        selected-total  (add selected-total amount.i.to-scan)
        to-scan  t.to-scan
      ==
    ::
        %execute
      ::  melt completed — check result
      =/  melt-result  (parse-melt-response:ca jon)
      ?~  melt-result
        ~&  >>>  %melt-bad-response
        ::  restore proofs
        =/  existing=(list cashu-proof)  (~(gut by wallet) mint.u.pm ~)
        =.  wallet  (~(put by wallet) mint.u.pm (weld existing proofs-used.u.pm))
        =.  pending-melts  (~(del by pending-melts) nonce)
        `this
      ?.  paid.u.melt-result
        ~&  >>>  [%melt-not-paid state.u.melt-result]
        ::  restore proofs
        =/  existing=(list cashu-proof)  (~(gut by wallet) mint.u.pm ~)
        =.  wallet  (~(put by wallet) mint.u.pm (weld existing proofs-used.u.pm))
        =.  pending-melts  (~(del by pending-melts) nonce)
        `this
      ::  success — proofs already removed from wallet
      ~&  >  %melt-success
      =.  pending-melts  (~(del by pending-melts) nonce)
      `this
    ==
  ==
++  on-fail   on-fail:def
--
