<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$publicHtmlFiles = [
    'index.html',
    'services/index.html',
    'web-developer-nigeria/index.html',
    'pricing.html',
];

function read_dom(string $path): DOMDocument
{
    $html = file_get_contents($path);
    if ($html === false) {
        throw new RuntimeException("Unable to read {$path}");
    }

    $dom = new DOMDocument();
    libxml_use_internal_errors(true);
    $dom->loadHTML($html);
    libxml_clear_errors();

    return $dom;
}

function attr(DOMXPath $xpath, string $query, string $attribute): ?string
{
    $nodes = $xpath->query($query);
    if (!$nodes || $nodes->length === 0) {
        return null;
    }

    $value = trim($nodes->item(0)->getAttribute($attribute));
    return $value !== '' ? $value : null;
}

function absolute_url(string $url, string $base): string
{
    if (preg_match('/^https?:\/\//i', $url)) {
        return $url;
    }

    $baseParts = parse_url($base);
    if (!$baseParts || empty($baseParts['scheme']) || empty($baseParts['host'])) {
        throw new RuntimeException("Invalid base URL {$base}");
    }

    $basePath = $baseParts['path'] ?? '/';
    $directory = preg_replace('#/[^/]*$#', '/', $basePath);

    if (str_starts_with($url, '/')) {
        $path = $url;
    } else {
        $path = $directory . $url;
    }

    $segments = [];
    foreach (explode('/', $path) as $segment) {
        if ($segment === '' || $segment === '.') {
            continue;
        }
        if ($segment === '..') {
            array_pop($segments);
            continue;
        }
        $segments[] = $segment;
    }

    return $baseParts['scheme'] . '://' . $baseParts['host'] . '/' . implode('/', $segments);
}

function text_node(DOMXPath $xpath, string $query): ?string
{
    $nodes = $xpath->query($query);
    if (!$nodes || $nodes->length === 0) {
        return null;
    }

    $value = trim($nodes->item(0)->textContent);
    return $value !== '' ? $value : null;
}

$pages = [];
$images = [];

foreach ($publicHtmlFiles as $relativePath) {
    $path = $root . '/' . $relativePath;
    $dom = read_dom($path);
    $xpath = new DOMXPath($dom);

    $robots = strtolower(attr($xpath, '//meta[translate(@name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")="robots"]', 'content') ?? '');
    if (str_contains($robots, 'noindex')) {
        continue;
    }

    $canonical = attr($xpath, '//link[translate(@rel, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")="canonical"]', 'href');
    if (!$canonical) {
        continue;
    }

    $alternates = [];
    foreach ($xpath->query('//link[translate(@rel, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")="alternate" and @hreflang]') ?: [] as $node) {
        $alternates[] = [
            'hreflang' => $node->getAttribute('hreflang'),
            'href' => $node->getAttribute('href'),
        ];
    }

    $pages[] = [
        'loc' => $canonical,
        'lastmod' => date('Y-m-d', filemtime($path) ?: time()),
        'changefreq' => $relativePath === 'pricing.html' ? 'monthly' : 'weekly',
        'priority' => $relativePath === 'index.html' ? '1.0' : (in_array($relativePath, ['services/index.html', 'web-developer-nigeria/index.html'], true) ? '0.9' : '0.8'),
        'alternates' => $alternates,
    ];

    $pageImages = [];
    $ogImage = attr($xpath, '//meta[@property="og:image"]', 'content');
    if ($ogImage) {
        $pageImages[$ogImage] = attr($xpath, '//meta[@property="og:image:alt"]', 'content') ?? text_node($xpath, '//title') ?? 'Social preview image';
    }

    foreach ($xpath->query('//img[@src]') ?: [] as $node) {
        $src = absolute_url($node->getAttribute('src'), $canonical);
        $alt = trim($node->getAttribute('alt')) ?: text_node($xpath, '//title') ?: 'Website image';
        $pageImages[$src] = $alt;
    }

    if ($relativePath === 'index.html') {
        $pageImages['https://dayoebe.github.io/files/mannarise-preview.svg'] = 'MannaRise project preview';
    }

    $images[$canonical] = $pageImages;
}

$xmlEscape = static fn (string $value): string => htmlspecialchars($value, ENT_XML1 | ENT_COMPAT, 'UTF-8');

$sitemapIndex = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
$sitemapIndex .= "<sitemapindex xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n";
foreach (['sitemap-pages.xml', 'sitemap-images.xml'] as $sitemap) {
    $sitemapIndex .= "  <sitemap>\n";
    $sitemapIndex .= "    <loc>https://dayoebe.github.io/{$sitemap}</loc>\n";
    $sitemapIndex .= '    <lastmod>' . date('Y-m-d') . "</lastmod>\n";
    $sitemapIndex .= "  </sitemap>\n";
}
$sitemapIndex .= "</sitemapindex>\n";
file_put_contents($root . '/sitemap.xml', $sitemapIndex);

$pagesXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
$pagesXml .= "<urlset\n  xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"\n  xmlns:xhtml=\"http://www.w3.org/1999/xhtml\">\n";
foreach ($pages as $page) {
    $pagesXml .= "  <url>\n";
    $pagesXml .= '    <loc>' . $xmlEscape($page['loc']) . "</loc>\n";
    foreach ($page['alternates'] as $alternate) {
        $pagesXml .= '    <xhtml:link rel="alternate" hreflang="' . $xmlEscape($alternate['hreflang']) . '" href="' . $xmlEscape($alternate['href']) . "\" />\n";
    }
    $pagesXml .= '    <lastmod>' . $page['lastmod'] . "</lastmod>\n";
    $pagesXml .= '    <changefreq>' . $page['changefreq'] . "</changefreq>\n";
    $pagesXml .= '    <priority>' . $page['priority'] . "</priority>\n";
    $pagesXml .= "  </url>\n";
}
$pagesXml .= "</urlset>\n";
file_put_contents($root . '/sitemap-pages.xml', $pagesXml);

$imagesXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
$imagesXml .= "<urlset\n  xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"\n  xmlns:image=\"http://www.google.com/schemas/sitemap-image/1.1\">\n";
foreach ($images as $loc => $pageImages) {
    $imagesXml .= "  <url>\n";
    $imagesXml .= '    <loc>' . $xmlEscape($loc) . "</loc>\n";
    foreach ($pageImages as $imageUrl => $title) {
        $imagesXml .= "    <image:image>\n";
        $imagesXml .= '      <image:loc>' . $xmlEscape($imageUrl) . "</image:loc>\n";
        $imagesXml .= '      <image:title>' . $xmlEscape($title) . "</image:title>\n";
        $imagesXml .= "    </image:image>\n";
    }
    $imagesXml .= "  </url>\n";
}
$imagesXml .= "</urlset>\n";
file_put_contents($root . '/sitemap-images.xml', $imagesXml);

echo "Generated sitemap.xml, sitemap-pages.xml, and sitemap-images.xml\n";
