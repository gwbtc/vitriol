::
::::  /mar/sh/hoon
  ::
/?    310
::
=,  eyre
|_  txt=@t
++  grow
  |%
  ++  mime  [/text/x-shellscript (as-octs:mimes:html txt)]
  --
++  grab
  |%
  ++  mime  |=([p=mite q=octs] (@t q.q))
  ++  noun  @t
  --
++  grad  %mime
--
