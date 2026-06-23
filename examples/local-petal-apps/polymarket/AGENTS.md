# Polymarket Agent Guide

Use this app through `/apps/polymarket`. Reads may fetch Polymarket market,
order-book, account, position, onboarding, and funding data. Writes under
`onboard`, `fund`, and `trade` stage or advance local workflows and may request
daemon-mediated signatures.

Do not treat draft, funding, onboarding, or receipt files as public data. The
package stores credentials under the secret `creds` namespace and order,
onboarding, trade, and funding state in private per-package storage.
