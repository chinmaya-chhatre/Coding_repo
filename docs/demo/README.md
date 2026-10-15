# HookScope signature lab (portfolio demo)

An interactive page that signs a sample webhook for GitHub, Stripe, Shopify, Slack, Twilio, Svix
and generic HMAC senders, then lets a visitor try to break the signature: tamper with the body,
re-format the JSON, use the wrong secret, make the request older, or simulate a proxy rewriting a
URL. Everything runs in the browser (Web Crypto); there is no backend and nothing is sent anywhere.

The verdicts are HookScope's: the tests run every scenario through this code and through
HookScope's Python verifiers and require identical results and reasons.

## Files

| Path | What it is |
|---|---|
| `dist/hookscope-demo.html` | **Upload this.** One file in the portfolio's look (its nav, footer, theme toggle, analytics). Expects to live at `/playground/hookscope-demo.html`. |
| `dist/standalone.html` | The same lab with its own styling. Works anywhere, including opened from disk. |
| `src/` | The sources: `providers.json` (the sample requests), `signing.js` (signing and verifying), `lab.js` and `lab.css` (the page), and the two page shells. |

Rebuild after changing `src/`: `python scripts/build_demo.py` (the tests fail if `dist/` is stale).

## Publish it on the portfolio (S3)

1. Upload the file next to the other playground pages:

   ```bash
   aws s3 cp docs/demo/dist/hookscope-demo.html \
     s3://YOUR-BUCKET/playground/hookscope-demo.html \
     --content-type "text/html; charset=utf-8" --cache-control "max-age=300"
   ```

   If the site sits behind CloudFront, invalidate `/playground/hookscope-demo.html` as well.

2. Add a card to `playground/playground.html`, in the **Live Now** grid beside the AWS Cost Monitor:

   ```html
   <div class="pg-card">
     <div class="pg-card-icon">&#x1F510;</div>
     <span class="pg-card-label">Integrations &middot; Webhooks</span>
     <p class="pg-card-title">Webhook Signature Lab</p>
     <p class="pg-card-desc">See how GitHub, Stripe, Shopify, Slack, Twilio and Svix sign their webhooks, then try to break the signature. The verification logic comes from HookScope, my open-source webhook receiver, and runs entirely in your browser.</p>
     <span class="pg-badge live">&#x1F7E2; Live</span>
     <a class="pg-card-link" href="hookscope-demo.html">Open the lab &#x2192;</a>
   </div>
   ```

3. Add the page to the menu in `js/nav.js`, under the `tech` group:

   ```js
   { label: 'Webhook signature lab', icon: '\u{1F510}', href: '/playground/hookscope-demo.html' },
   ```

   Then bump the cache-busting version on every page that loads it (`/js/nav.js?v=20261011`) so
   visitors get the new menu.

4. Optionally link it from the HookScope row of whatever page describes the project, and from the
   README of the HookScope repo.

## Notes

- The page loads the site's `/css/style.css`, `/js/nav.js` and `/js/analytics.js`, so it must be
  served from the site root; opening it from disk shows it unstyled (use `standalone.html` for that).
- Its own styles are scoped under `#hs-lab`, so they cannot affect the rest of the site.
- The secrets on the page are public demo values. The Svix one is the example from Svix's
  documentation; GitHub's secret scanner may flag it as a false positive, which can be dismissed
  as "used in tests".
