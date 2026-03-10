<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$iconDir = $root . '/icons';
$fontPath = '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf';

if (!extension_loaded('gd')) {
    fwrite(STDERR, "The GD extension is required to generate icons.\n");
    exit(1);
}

if (!is_dir($iconDir) && !mkdir($iconDir, 0775, true) && !is_dir($iconDir)) {
    fwrite(STDERR, "Unable to create icon directory: {$iconDir}\n");
    exit(1);
}

renderIcon($iconDir . '/icon-192.png', 192, 'AEO', 48, 40);
renderIcon($iconDir . '/icon-512.png', 512, 'AEO', 126, 84);
renderIcon($iconDir . '/icon-maskable-512.png', 512, 'AEO', 116, 118);
renderIcon($iconDir . '/apple-touch-icon.png', 180, 'AEO', 44, 34);
renderIcon($iconDir . '/favicon-32.png', 32, 'A', 14, 6);
renderIcon($iconDir . '/favicon-16.png', 16, 'A', 8, 3);

function renderIcon(string $path, int $size, string $label, int $fontSize, int $safeInset): void
{
    global $fontPath;

    $image = imagecreatetruecolor($size, $size);
    imagealphablending($image, true);
    imagesavealpha($image, false);

    $red = imagecolorallocate($image, 220, 38, 38);
    $orange = imagecolorallocatealpha($image, 251, 146, 60, 30);
    $white = imagecolorallocate($image, 255, 247, 237);
    $softRed = imagecolorallocate($image, 254, 226, 226);
    $dark = imagecolorallocatealpha($image, 24, 24, 27, 90);
    $shadow = imagecolorallocatealpha($image, 24, 24, 27, 118);
    $accent = imagecolorallocatealpha($image, 255, 255, 255, 66);
    $text = imagecolorallocate($image, 185, 28, 28);

    imagefilledrectangle($image, 0, 0, $size, $size, $red);

    imagefilledellipse(
        $image,
        (int) round($size * 0.77),
        (int) round($size * 0.23),
        (int) round($size * 0.30),
        (int) round($size * 0.30),
        $orange
    );

    filledRoundedRectangle($image, $safeInset, $safeInset, $size - $safeInset, $size - $safeInset, (int) round($size * 0.18), $dark);

    $panelLeft = (int) round($size * 0.20);
    $panelTop = (int) round($size * 0.29);
    $panelRight = $size - $panelLeft;
    $panelBottom = (int) round($size * 0.72);
    filledRoundedRectangle($image, $panelLeft, $panelTop, $panelRight, $panelBottom, (int) round($size * 0.09), $white);

    $bannerInsetX = (int) round($size * 0.08);
    $bannerInsetY = (int) round($size * 0.11);
    filledRoundedRectangle(
        $image,
        $panelLeft + $bannerInsetX,
        $panelTop + $bannerInsetY,
        $panelRight - $bannerInsetX,
        (int) round($panelTop + $bannerInsetY + $size * 0.14),
        (int) round($size * 0.05),
        $softRed
    );

    $bbox = imagettfbbox($fontSize, 0, $fontPath, $label);
    $textWidth = abs($bbox[2] - $bbox[0]);
    $textHeight = abs($bbox[7] - $bbox[1]);
    $textX = (int) round(($size - $textWidth) / 2);
    $textY = (int) round(($size + $textHeight) / 2);
    imagettftext($image, $fontSize, 0, $textX, $textY, $text, $fontPath, $label);

    filledRoundedRectangle(
        $image,
        (int) round($size * 0.31),
        (int) round($size * 0.67),
        (int) round($size * 0.69),
        (int) round($size * 0.71),
        (int) round($size * 0.02),
        $shadow
    );

    filledRoundedRectangle(
        $image,
        (int) round($size * 0.36),
        (int) round($size * 0.20),
        (int) round($size * 0.64),
        (int) round($size * 0.24),
        (int) round($size * 0.02),
        $accent
    );

    imagepng($image, $path);
    imagedestroy($image);
}

function filledRoundedRectangle(GdImage $image, int $x1, int $y1, int $x2, int $y2, int $radius, int $color): void
{
    $diameter = $radius * 2;

    imagefilledrectangle($image, $x1 + $radius, $y1, $x2 - $radius, $y2, $color);
    imagefilledrectangle($image, $x1, $y1 + $radius, $x2, $y2 - $radius, $color);

    imagefilledellipse($image, $x1 + $radius, $y1 + $radius, $diameter, $diameter, $color);
    imagefilledellipse($image, $x2 - $radius, $y1 + $radius, $diameter, $diameter, $color);
    imagefilledellipse($image, $x1 + $radius, $y2 - $radius, $diameter, $diameter, $color);
    imagefilledellipse($image, $x2 - $radius, $y2 - $radius, $diameter, $diameter, $color);
}
