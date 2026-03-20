::  /lib/vitriol-ui/hoon
::  Sail UI for vitriol — landing page and admin panel
::
::  Arms:
::    html-response       — wrap a manx page in an HTTP 200 response
::    redirect-response   — HTTP 303 redirect
::    render-home         — landing page with app description and endpoint docs
::    render-admin        — admin panel split into committer and maintainer sections
::
/-  *vitriol
/+  server
|%
++  html-response
  |=  [eyre-id=@ta page=manx]
  ^-  (list card:agent:gall)
  =/  bod=octs
    (as-octs:mimes:html (crip (en-xml:html page)))
  %+  give-simple-payload:app:server  eyre-id
  :-  :-  200
      :~  ['content-type' 'text/html; charset=utf-8']
      ==
  [~ bod]
::
++  redirect-response
  |=  [eyre-id=@ta url=@t]
  ^-  (list card:agent:gall)
  %+  give-simple-payload:app:server  eyre-id
  :-  [303 ~[['location' url]]]
  ~
::
++  css
  ^-  tape
  %-  trip
  '''
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: monospace; background: #111; color: #e0e0e0;
         max-width: 640px; margin: 0 auto; padding: 24px; }
  h1 { color: #0f0; margin-bottom: 4px; font-size: 1.4em; }
  h1 a { color: #0f0; text-decoration: none; }
  h1 a:hover { text-decoration: underline; }
  .sub { color: #666; margin-bottom: 24px; }
  .sub a { color: #666; }
  .sub a:hover { color: #0f0; }
  section { background: #1a1a1a; border: 1px solid #333;
            border-radius: 4px; padding: 16px; margin-bottom: 16px; }
  h2 { color: #0a0; font-size: 1em; margin-bottom: 12px;
       border-bottom: 1px solid #333; padding-bottom: 8px; }
  h3 { color: #888; font-size: 0.85em; text-transform: uppercase;
       letter-spacing: 1px; margin-bottom: 12px; }
  p { line-height: 1.5; margin-bottom: 12px; }
  code { background: #222; padding: 2px 6px; border-radius: 3px; color: #0f0; }
  pre { background: #222; padding: 12px; border-radius: 4px;
        overflow-x: auto; margin-bottom: 12px; color: #0f0; }
  label { display: block; color: #888; font-size: 0.85em; margin-bottom: 2px; }
  .val { color: #0f0; word-break: break-all; margin-bottom: 12px; }
  .ship-row { display: flex; align-items: center; justify-content: space-between;
              padding: 6px 8px; background: #222; border-radius: 3px; margin-bottom: 4px; }
  .ship-row span { color: #e0e0e0; }
  input[type=text], input[type=number] {
    background: #222; border: 1px solid #444; color: #e0e0e0;
    padding: 6px 8px; border-radius: 3px; font-family: monospace;
    width: 100%; margin-bottom: 8px; }
  input[type=text]:focus, input[type=number]:focus { outline: none; border-color: #0a0; }
  button, input[type=submit] {
    background: #222; border: 1px solid #444; color: #0f0;
    padding: 6px 12px; border-radius: 3px; cursor: pointer;
    font-family: monospace; font-size: 0.9em; }
  button:hover, input[type=submit]:hover { background: #333; border-color: #0f0; }
  .btn-danger { color: #f44; border-color: #a33; }
  .btn-danger:hover { border-color: #f44; }
  .toggle-form { display: flex; align-items: center; gap: 12px; }
  .status { display: inline-block; padding: 2px 8px; border-radius: 3px;
            font-size: 0.85em; }
  .status-on { background: #0a2e0a; color: #0f0; border: 1px solid #0a0; }
  .status-off { background: #2e0a0a; color: #f44; border: 1px solid #a33; }
  .empty { color: #666; font-style: italic; padding: 8px 0; }
  .balance { font-size: 1.2em; color: #ff0; margin-bottom: 12px; }
  .pending { color: #fa0; font-size: 0.85em; }
  .inline-form { display: flex; gap: 8px; align-items: flex-end; }
  .inline-form input { margin-bottom: 0; }
  .nav { margin-bottom: 16px; }
  .nav a { color: #0a0; margin-right: 16px; text-decoration: none; }
  .nav a:hover { color: #0f0; text-decoration: underline; }
  .divider { border: 0; border-top: 1px solid #333; margin: 24px 0 16px; }
  '''
::
::  -- Landing page --
::
++  render-home
  |=  our=@p
  ^-  manx
  ;html
    ;head
      ;title: vitriol
      ;style
        ;+  ;/  css
      ==
    ==
    ;body
      ;h1: vitriol
      ;div.sub: groundwire for github · {(trip (scot %p our))}
      ;div.nav
        ;a(href "/vitriol/admin"): admin panel
      ==
      ;section
        ;h2: what is vitriol?
        ;p: vitriol is an Urbit agent that bridges on-chain identity to git workflows. it lets you sign commits with your ship's Ed25519 networking key — the same key attested on-chain via a Groundwire inscription — and verify those signatures in CI.
        ;p: optionally, maintainers can require ecash token payments with each signed commit, and committers can load their wallet with sats via Lightning to include with their signatures.
      ==
      ;section
        ;h2: how it works
        ;h3: for committers (signers)
        ;p: install the pre-commit hook in your repo. when you commit, the hook calls your ship's vitriol agent to sign the commit content with your networking key. the signature and your @p are embedded in the commit message.
        ;pre: ./hooks/install.sh
        ;p: if the maintainer requires ecash payment, configure your ship's mint and load sats in the admin panel. the hook will select tokens from your wallet and include them in the signature block.
        ;h3: for maintainers (verifiers)
        ;p: add vitriol's verify-commit endpoint to your CI pipeline. it checks the commit signature against the signer's on-chain Groundwire key via Jael.
        ;pre: POST /vitriol/verify-commit
        ;p: you can also require ecash payment, manage a ban list of @p's, and expose your encryption pubkey for receiving tokens — all from the admin panel.
      ==
      ;section
        ;h2: endpoints
        ;h3: signing
        ;p
          ;code: POST /vitriol/sign
          ;span:  — sign commit content with your networking key
        ==
        ;h3: verification
        ;p
          ;code: POST /vitriol/verify-commit
          ;span:  — verify a signature against on-chain key
        ==
        ;p
          ;code: GET /vitriol/verify-status/[id]
          ;span:  — poll for async ecash verification result
        ==
        ;h3: identity
        ;p
          ;code: GET /vitriol/pubkey
          ;span:  — your on-chain networking public key
        ==
        ;p
          ;code: GET /vitriol/ecash-pubkey
          ;span:  — your ecash encryption public key
        ==
        ;p
          ;code: GET /vitriol/check-id/~ship
          ;span:  — check if a ship has a Groundwire ID
        ==
        ;h3: ban list
        ;p
          ;code: GET /vitriol/banned
          ;span:  — list banned ships
        ==
        ;p
          ;code: POST /vitriol/ban
          ;span:  — ban a ship (JSON body)
        ==
        ;p
          ;code: POST /vitriol/unban
          ;span:  — unban a ship (JSON body)
        ==
        ;h3: ecash
        ;p
          ;code: GET /vitriol/sats-per-pr
          ;span:  — maintainer's price per PR (in sats)
        ==
      ==
    ==
  ==
::
::  -- Admin panel --
::
++  render-admin
  |=  $:  our=@p
          ecash-key=(unit [sec=@ pub=@])
          banned=(set @p)
          require-payment=?
          sats-per-pr=(unit @ud)
          public-verify=?
          mint=(unit @t)
          wallet=(map @t (list cashu-proof))
          pending-mints=(map @t pending-mint-quote)
          pending-melts=(map @t pending-melt)
          to-hex=$-([@ud @] @t)
      ==
  ^-  manx
  =/  ships=(list @p)  ~(tap in banned)
  =/  num-melts=@ud  ~(wyt by pending-melts)
  =/  wallet-entries=(list [@t @ud @ud])
    %+  murn  ~(tap by wallet)
    |=  [m=@t proofs=(list cashu-proof)]
    =/  total=@ud  (roll proofs |=([p=cashu-proof a=@ud] (add a amount.p)))
    ?:  =(0 total)  ~
    `[m total (lent proofs)]
  =/  balance=@ud
    %-  ~(rep by wallet)
    |=  [[m=@t proofs=(list cashu-proof)] acc=@ud]
    (add acc (roll proofs |=([p=cashu-proof a=@ud] (add a amount.p))))
  =/  num-pending=@ud  ~(wyt by pending-mints)
  ;html
    ;head
      ;title: vitriol admin
      ;style
        ;+  ;/  css
      ==
    ==
    ;body
      ;h1
        ;a(href "/vitriol"): vitriol
      ==
      ;div.sub
        ;span: admin panel · {(trip (scot %p our))} ·
        ;a(href "/vitriol"): home
      ==
      ;h3: committer
      ;section
        ;h2: wallet
        ;div.balance: {(trip (scot %ud balance))} sats
        ;+  ?:  (gth num-pending 0)
              ;div.pending: {(trip (scot %ud num-pending))} pending invoice(s) — waiting for payment...
            ;div;
        ;label: mint url
        ;form(method "POST", action "/vitriol/admin/set-mint")
          ;div.inline-form
            ;input(type "text", name "mint", placeholder "https://mint.example.com", value ?~(mint "" (trip u.mint)));
            ;input(type "submit", value "Set mint");
          ==
        ==
        ;+  ?~  mint
              ;div.empty: set a mint url to load sats
            ;div
              ;label: load sats via lightning
              ;form(method "POST", action "/vitriol/admin/load-sats")
                ;div.inline-form
                  ;input(type "number", name "amount", placeholder "100", min "1");
                  ;input(type "submit", value "Get invoice");
                ==
              ==
            ==
      ==
      ;hr.divider;
      ;h3: maintainer
      ;section
        ;h2: ecash payment
        ;div.toggle-form
          ;span
            ;+  ?:  require-payment
                  ;span.status.status-on: required
                ;span.status.status-off: not required
          ==
          ;form(method "POST", action "/vitriol/admin/toggle-payment")
            ;input(type "submit", value ?:(require-payment "Disable" "Enable"));
          ==
        ==
        ;label: sats per PR
        ;form(method "POST", action "/vitriol/admin/set-price")
          ;div.inline-form
            ;input(type "number", name "price", placeholder "0", min "0", value ?~(sats-per-pr "" (trip (scot %ud u.sats-per-pr))));
            ;input(type "submit", value "Set price");
          ==
        ==
        ;+  ?~  ecash-key
              ;div.val: no keypair generated
            ;div
              ;label: encryption public key (for receiving ecash)
              ;div.val: {(trip (to-hex 64 pub.u.ecash-key))}
            ==
      ==
      ;section
        ;h2: public verification
        ;div.toggle-form
          ;span
            ;+  ?:  public-verify
                  ;span.status.status-on: enabled
                ;span.status.status-off: disabled
          ==
          ;form(method "POST", action "/vitriol/admin/toggle-public-verify")
            ;input(type "submit", value ?:(public-verify "Disable" "Enable"));
          ==
        ==
        ;p: when enabled, /vitriol/verify-commit, /vitriol/verify-status, /vitriol/sats-per-pr, and /vitriol/ecash-pubkey are accessible without authentication. this allows other repos to use your ship for CI verification without needing an auth cookie.
      ==
      ;section
        ;h2: received tokens
        ;+  ?:  (gth num-melts 0)
              ;div.pending: withdrawal in progress...
            ;div;
        ;+  ?:  =(~ wallet-entries)
              ;div.empty: no tokens received yet
            ;div
              ;*  %+  turn  wallet-entries
                  |=  [m=@t total=@ud count=@ud]
                  ^-  manx
                  ;div
                    ;label: {(trip m)}
                    ;div.val: {(trip (scot %ud total))} sats ({(trip (scot %ud count))} proofs)
                    ;form(method "POST", action "/vitriol/admin/withdraw")
                      ;input(type "hidden", name "mint", value (trip m));
                      ;label: lightning invoice
                      ;input(type "text", name "invoice", placeholder "lnbc...");
                      ;input(type "submit", value "Withdraw to Lightning");
                    ==
                  ==
            ==
      ==
      ;section
        ;h2: ban list ({(trip (scot %ud (lent ships)))})
        ;form(method "POST", action "/vitriol/admin/ban")
          ;input(type "text", name "ship", placeholder "~sampel-palnet");
          ;input(type "submit", value "Ban ship");
        ==
        ;br;
        ;+  ?:  =(~ ships)
              ;div.empty: no banned ships
            ;div
              ;*  %+  turn  ships
                  |=  s=@p
                  ^-  manx
                  ;div.ship-row
                    ;span: {(trip (scot %p s))}
                    ;form(method "POST", action "/vitriol/admin/unban", style "margin:0")
                      ;input(type "hidden", name "ship", value "{(trip (scot %p s))}");
                      ;button.btn-danger(type "submit"): remove
                    ==
                  ==
            ==
      ==
    ==
  ==
--
