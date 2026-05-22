# SEO and AI Discoverability Report

Date: 2026-05-22

## 1. Project Stack Detected

- Stack: static HTML portfolio/PWA hosted for `https://dayoebe.github.io/`.
- Rendering: static HTML with client-side JavaScript enhancements.
- Main public routes: `/`, `/services/`, `/pricing.html`.
- No CMS, database, SSR, SSG, WordPress, Laravel runtime, Next.js, or build pipeline was found.
- Frontend dependencies: Tailwind CDN, Font Awesome CDN, Google Fonts, Alpine.js on the homepage, local `assets/i18n.js`, local `assets/currency.js`, and a service worker.
- Metadata is controlled directly in each HTML `<head>`. Homepage and pricing metadata can also be updated client-side by `assets/i18n.js` when language changes.
- Sitemap and robots are static files. A generator now exists at `tools/generate-sitemaps.php`.
- Multilingual content exists on the homepage and pricing page through the shared language system. Services are currently English only.

## 2. SEO Issues Found

- `robots.txt` was too broad and had no documented AI/search crawler policy.
- `sitemap.xml` was a single page sitemap and did not include an image sitemap or sitemap index.
- `llms.txt` existed but was too thin for agent discovery and did not link to a fuller AI-readable brief.
- No `/llms-full.txt` or `/ai.txt` existed.
- Services FAQ schema existed before the exact FAQ content was visible on the page.
- Services and pricing pages had incomplete social image metadata compared with the homepage.
- Offline and redirect helper pages were public without explicit noindex metadata.
- Some important project content was only present in progressive enhancement JavaScript. MannaRise is now represented in static HTML.
- Project images did not consistently have explicit width and height attributes.

## 3. AI Discoverability Issues Found

- AI-readable documentation was incomplete.
- The site did not clearly explain freshness, citation format, sitemap location, and absence of a feed.
- Training crawler policy was not separated from AI search/discovery crawler policy.
- Key service and pricing facts were present visually but not summarized in full Markdown for LLMs and agents.

## 4. Files Changed

- `index.html`
- `pricing.html`
- `services/index.html`
- `robots.txt`
- `sitemap.xml`
- `service-worker.js`
- `llms.txt`
- `offline.html`
- `404.html`
- `dayo/index.html`
- `adedayo-ebenezer-oyetoke-cv.html`

## 5. Files Created

- `sitemap-pages.xml`
- `sitemap-images.xml`
- `llms-full.txt`
- `ai.txt`
- `tools/generate-sitemaps.php`
- `docs/seo-ai-discoverability-report.md`

## 6. Schema Types Implemented

- `Person`
- `Organization`
- `WebSite`
- `WebPage`
- `BreadcrumbList`
- `ProfessionalService`
- `OfferCatalog`
- `Offer`
- `FAQPage`
- `ContactPoint`
- `ImageObject`

No fake reviews, ratings, products, inventory, opening hours, job postings, medical schema, restaurant schema, podcast schema, or article schema were added.

## 7. Sitemap and Feed Status

- `/sitemap.xml` is now a sitemap index.
- `/sitemap-pages.xml` includes the public canonical pages.
- `/sitemap-images.xml` includes the social preview, portrait, and project imagery.
- `tools/generate-sitemaps.php` regenerates sitemap files from the public HTML page list.
- No RSS or Atom feed was added because the site currently has no blog, news, article, podcast, or feed-based content.

## 8. Robots.txt Policy

- Public pages and render assets are crawlable.
- Internal implementation paths such as `.git`, `.codex`, `docs`, and `tools` are disallowed.
- Googlebot, Bingbot, DuckDuckBot, OAI-SearchBot, ChatGPT-User, and PerplexityBot are explicitly supported for search/discovery.
- GPTBot, ClaudeBot, CCBot, and Google-Extended are blocked by default as training/research crawlers until the site owner opts in.
- Sitemap reference points to `https://dayoebe.github.io/sitemap.xml`.

## 9. LLM Files Summary

- `/llms.txt` now gives a concise official summary, core pages, main topics, priority content, citation guidance, and freshness notes.
- `/llms-full.txt` now gives a fuller Markdown brief with services, pricing, target audience, project summaries, contact details, schema guidance, and non-inference rules.
- `/ai.txt` now states AI usage and citation guidance for public pages.

## 10. Performance and Accessibility Improvements

- Added explicit width and height attributes to major project and portrait images.
- Kept non-critical project images lazy-loaded.
- Added missing social image dimensions and alt metadata on secondary pages.
- Added visible breadcrumbs to services and pricing pages.
- Added explicit noindex metadata to offline and redirect helper pages.
- Added a visible services FAQ section so FAQ schema matches page content.
- Bumped service worker cache names and cached new discovery files.

## 11. Remaining TODOs

- Decide whether to opt into GPTBot, ClaudeBot, CCBot, or Google-Extended crawling for model training.
- If a blog, news, or articles section is added later, add RSS/Atom feed discovery and Article/BlogPosting schema.
- If a physical office with public hours is added later, add truthful LocalBusiness data.
- Add a production build pipeline for Tailwind instead of relying on the Tailwind CDN if performance budgets become stricter.
- Consider self-hosting fonts and icons to reduce third-party render dependencies.
- Add automated deployment steps that run `php tools/generate-sitemaps.php` before publishing.
- Validate the live domain after deployment because local checks cannot confirm GitHub Pages CDN headers.

## 12. Manual Steps For The Site Owner

- Submit `https://dayoebe.github.io/sitemap.xml` in Google Search Console.
- Submit `https://dayoebe.github.io/sitemap.xml` in Bing Webmaster Tools.
- Verify `https://dayoebe.github.io/robots.txt` after deployment.
- Test rich results for homepage, services, and pricing pages.
- Test social previews for Facebook, X/Twitter, WhatsApp, LinkedIn, and Telegram.
- Check important pages in Google indexing reports after recrawl.
- Keep project, pricing, and contact information updated.
- Build external authority through mentions, backlinks, citations, directories, and social profiles.
- Maintain factual consistency across the website, GitHub, LinkedIn, social profiles, and directories.
