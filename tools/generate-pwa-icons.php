<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$iconDir = $root . '/icons';
$sourcePath = $root . '/passport.png';

if (!extension_loaded('gd')) {
    fwrite(STDERR, "The GD extension is required to generate icons.\n");
    exit(1);
}

if (!is_dir($iconDir) && !mkdir($iconDir, 0775, true) && !is_dir($iconDir)) {
    fwrite(STDERR, "Unable to create icon directory: {$iconDir}\n");
    exit(1);
}

if (!is_file($sourcePath)) {
    fwrite(STDERR, "Icon source not found: {$sourcePath}\n");
    exit(1);
}

$sourceData = file_get_contents($sourcePath);
$sourceImage = $sourceData !== false ? imagecreatefromstring($sourceData) : false;

if (!$sourceImage instanceof GdImage) {
    fwrite(STDERR, "Unable to read passport image: {$sourcePath}\n");
    exit(1);
}

$sourceWidth = imagesx($sourceImage);
$sourceHeight = imagesy($sourceImage);
$cropSize = min($sourceWidth, $sourceHeight);
$cropX = (int) floor(($sourceWidth - $cropSize) / 2);
$cropY = (int) floor(($sourceHeight - $cropSize) / 2);

renderPhotoIcon($sourceImage, $iconDir . '/icon-192.png', 192, 0);
renderPhotoIcon($sourceImage, $iconDir . '/icon-512.png', 512, 0);
renderPhotoIcon($sourceImage, $iconDir . '/icon-maskable-512.png', 512, 56);
renderPhotoIcon($sourceImage, $iconDir . '/apple-touch-icon.png', 180, 0);
renderPhotoIcon($sourceImage, $iconDir . '/favicon-32.png', 32, 0);
renderPhotoIcon($sourceImage, $iconDir . '/favicon-16.png', 16, 0);

imagedestroy($sourceImage);

function renderPhotoIcon(GdImage $sourceImage, string $path, int $size, int $inset): void
{
    global $cropSize, $cropX, $cropY;

    $image = imagecreatetruecolor($size, $size);
    imagealphablending($image, true);
    imagesavealpha($image, false);

    $background = imagecolorallocate($image, 245, 245, 244);
    imagefilledrectangle($image, 0, 0, $size, $size, $background);

    imagecopyresampled(
        $image,
        $sourceImage,
        $inset,
        $inset,
        $cropX,
        $cropY,
        $size - ($inset * 2),
        $size - ($inset * 2),
        $cropSize,
        $cropSize
    );

    imagepng($image, $path);
    imagedestroy($image);
}
