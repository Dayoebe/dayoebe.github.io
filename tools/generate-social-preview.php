<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$sourcePath = $root . '/passport.png';
$outputPath = $root . '/social-preview.jpg';

if (!extension_loaded('gd')) {
    fwrite(STDERR, "The GD extension is required to generate the social preview.\n");
    exit(1);
}

if (!is_file($sourcePath)) {
    fwrite(STDERR, "Preview source not found: {$sourcePath}\n");
    exit(1);
}

$sourceData = file_get_contents($sourcePath);
$sourceImage = $sourceData !== false ? imagecreatefromstring($sourceData) : false;

if (!$sourceImage instanceof GdImage) {
    fwrite(STDERR, "Unable to read passport image: {$sourcePath}\n");
    exit(1);
}

$width = 1200;
$height = 630;
$image = imagecreatetruecolor($width, $height);
imageantialias($image, true);

$background = imagecolorallocate($image, 250, 250, 249);
$panel = imagecolorallocate($image, 255, 255, 255);
$panelBorder = imagecolorallocate($image, 231, 229, 228);
$red = imagecolorallocate($image, 220, 38, 38);
$redDark = imagecolorallocate($image, 153, 27, 27);
$redSoft = imagecolorallocate($image, 254, 226, 226);
$redBorder = imagecolorallocate($image, 254, 202, 202);
$dark = imagecolorallocate($image, 24, 24, 27);
$slate = imagecolorallocate($image, 51, 65, 85);
$muted = imagecolorallocate($image, 82, 82, 91);
$photoBorder = imagecolorallocate($image, 214, 211, 209);

imagefilledrectangle($image, 0, 0, $width, $height, $background);
roundedRectangle($image, 40, 40, 1160, 590, 28, $panel);
roundedRectangleOutline($image, 40, 40, 1160, 590, 28, $panelBorder, 4);

roundedRectangle($image, 80, 92, 310, 136, 22, $redSoft);
roundedRectangleOutline($image, 80, 92, 310, 136, 22, $redBorder, 2);

$fontRegular = '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf';
$fontBold = '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf';

drawCenteredText($image, 'Wireless Terminal', $fontBold, 18, 80, 310, 121, $redDark);
drawFittedText($image, 'Adedayo Ebenezer', $fontBold, 58, 80, 720, 224, $dark);
drawFittedText($image, 'Oyetoke', $fontBold, 58, 80, 720, 298, $red);
drawFittedText($image, 'Full-Stack Web Developer', $fontBold, 34, 80, 720, 370, $slate);
imagettftext($image, 26, 0, 80, 424, $muted, $fontRegular, 'Laravel | Vue.js | React');
imagettftext($image, 26, 0, 80, 466, $muted, $fontRegular, 'EdTech | Digital Growth');

roundedRectangle($image, 80, 500, 420, 556, 14, $red);
drawCenteredText($image, 'dayoebe.github.io', $fontBold, 24, 80, 420, 536, imagecolorallocate($image, 255, 255, 255));

$photoSize = 330;
$photoX = 810;
$photoY = 150;
roundedRectangle($image, $photoX - 12, $photoY - 12, $photoX + $photoSize + 12, $photoY + $photoSize + 12, 26, $photoBorder);
roundedRectangle($image, $photoX, $photoY, $photoX + $photoSize, $photoY + $photoSize, 20, $panel);
copyCover($image, $sourceImage, $photoX, $photoY, $photoSize, $photoSize);
roundedRectangleOutline($image, $photoX, $photoY, $photoX + $photoSize, $photoY + $photoSize, 20, $panel, 5);

imagejpeg($image, $outputPath, 92);
imagedestroy($image);
imagedestroy($sourceImage);

function copyCover(GdImage $target, GdImage $source, int $x, int $y, int $width, int $height): void
{
    $sourceWidth = imagesx($source);
    $sourceHeight = imagesy($source);
    $sourceRatio = $sourceWidth / $sourceHeight;
    $targetRatio = $width / $height;

    if ($sourceRatio > $targetRatio) {
        $cropHeight = $sourceHeight;
        $cropWidth = (int) round($sourceHeight * $targetRatio);
        $cropX = (int) floor(($sourceWidth - $cropWidth) / 2);
        $cropY = 0;
    } else {
        $cropWidth = $sourceWidth;
        $cropHeight = (int) round($sourceWidth / $targetRatio);
        $cropX = 0;
        $cropY = (int) floor(($sourceHeight - $cropHeight) / 2);
    }

    imagecopyresampled($target, $source, $x, $y, $cropX, $cropY, $width, $height, $cropWidth, $cropHeight);
}

function roundedRectangle(GdImage $image, int $x1, int $y1, int $x2, int $y2, int $radius, int $color): void
{
    imagefilledrectangle($image, $x1 + $radius, $y1, $x2 - $radius, $y2, $color);
    imagefilledrectangle($image, $x1, $y1 + $radius, $x2, $y2 - $radius, $color);
    imagefilledellipse($image, $x1 + $radius, $y1 + $radius, $radius * 2, $radius * 2, $color);
    imagefilledellipse($image, $x2 - $radius, $y1 + $radius, $radius * 2, $radius * 2, $color);
    imagefilledellipse($image, $x1 + $radius, $y2 - $radius, $radius * 2, $radius * 2, $color);
    imagefilledellipse($image, $x2 - $radius, $y2 - $radius, $radius * 2, $radius * 2, $color);
}

function roundedRectangleOutline(GdImage $image, int $x1, int $y1, int $x2, int $y2, int $radius, int $color, int $thickness): void
{
    for ($offset = 0; $offset < $thickness; $offset++) {
        imageline($image, $x1 + $radius, $y1 + $offset, $x2 - $radius, $y1 + $offset, $color);
        imageline($image, $x1 + $radius, $y2 - $offset, $x2 - $radius, $y2 - $offset, $color);
        imageline($image, $x1 + $offset, $y1 + $radius, $x1 + $offset, $y2 - $radius, $color);
        imageline($image, $x2 - $offset, $y1 + $radius, $x2 - $offset, $y2 - $radius, $color);
        imagearc($image, $x1 + $radius, $y1 + $radius, ($radius - $offset) * 2, ($radius - $offset) * 2, 180, 270, $color);
        imagearc($image, $x2 - $radius, $y1 + $radius, ($radius - $offset) * 2, ($radius - $offset) * 2, 270, 360, $color);
        imagearc($image, $x1 + $radius, $y2 - $radius, ($radius - $offset) * 2, ($radius - $offset) * 2, 90, 180, $color);
        imagearc($image, $x2 - $radius, $y2 - $radius, ($radius - $offset) * 2, ($radius - $offset) * 2, 0, 90, $color);
    }
}

function drawCenteredText(GdImage $image, string $text, string $font, int $size, int $x1, int $x2, int $baselineY, int $color): void
{
    $box = imagettfbbox($size, 0, $font, $text);
    $textWidth = $box === false ? 0 : $box[2] - $box[0];
    $x = (int) round($x1 + (($x2 - $x1 - $textWidth) / 2));
    imagettftext($image, $size, 0, $x, $baselineY, $color, $font, $text);
}

function drawFittedText(GdImage $image, string $text, string $font, int $maxSize, int $x, int $maxX, int $baselineY, int $color): void
{
    $size = $maxSize;

    while ($size > 18) {
        $box = imagettfbbox($size, 0, $font, $text);
        $textWidth = $box === false ? 0 : $box[2] - $box[0];

        if ($x + $textWidth <= $maxX) {
            break;
        }

        $size -= 2;
    }

    imagettftext($image, $size, 0, $x, $baselineY, $color, $font, $text);
}
