<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');

function respond(int $statusCode, bool $ok, string $message): void
{
    http_response_code($statusCode);
    echo json_encode([
        'ok' => $ok,
        'message' => $message,
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function str_length(string $value): int
{
    if (function_exists('mb_strlen')) {
        return mb_strlen($value);
    }

    return strlen($value);
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    respond(405, false, 'Method not allowed.');
}

$honeypot = trim((string)($_POST['company'] ?? ''));
if ($honeypot !== '') {
    respond(200, true, 'Message sent successfully.');
}

$name = trim((string)($_POST['name'] ?? ''));
$email = trim((string)($_POST['email'] ?? ''));
$subject = trim((string)($_POST['subject'] ?? ''));
$message = trim((string)($_POST['message'] ?? ''));

if ($name === '' || str_length($name) < 2 || str_length($name) > 80) {
    respond(422, false, 'Please provide a valid name.');
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL) || str_length($email) > 120) {
    respond(422, false, 'Please provide a valid email address.');
}

if ($subject === '' || str_length($subject) < 4 || str_length($subject) > 120) {
    respond(422, false, 'Please provide a valid subject.');
}

if ($message === '' || str_length($message) < 20 || str_length($message) > 2500) {
    respond(422, false, 'Message must be between 20 and 2500 characters.');
}

$ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$rateLimitKey = preg_replace('/[^a-zA-Z0-9:\.\-]/', '_', $ipAddress);
$rateLimitFile = sys_get_temp_dir() . '/portfolio_contact_' . sha1($rateLimitKey) . '.txt';
$now = time();
$coolDownSeconds = 30;

if (is_file($rateLimitFile)) {
    $lastSent = (int)trim((string)file_get_contents($rateLimitFile));
    if ($lastSent > 0 && ($now - $lastSent) < $coolDownSeconds) {
        respond(429, false, 'Please wait before sending another message.');
    }
}

@file_put_contents($rateLimitFile, (string)$now, LOCK_EX);

$recipient = 'oyetoke.ebenezer@gmail.com';
$fromAddress = 'no-reply@wirelesscs.ct.ws';

$safeName = preg_replace('/[^a-zA-Z0-9\s\.\-\']/u', '', $name) ?: 'Portfolio Visitor';
$safeSubject = preg_replace('/[\r\n]+/', ' ', $subject);
$safeMessage = preg_replace("/\r\n?|\n/", "\n", $message);

$mailSubject = 'Portfolio Contact: ' . $safeSubject;
$mailBody = "New portfolio contact form message\n\n"
    . "Name: {$safeName}\n"
    . "Email: {$email}\n"
    . "Subject: {$safeSubject}\n"
    . "IP Address: {$ipAddress}\n"
    . "Submitted: " . gmdate('Y-m-d H:i:s') . " UTC\n\n"
    . "Message:\n{$safeMessage}\n";

$headers = [
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'From: Wireless Portfolio <' . $fromAddress . '>',
    'Reply-To: ' . $safeName . ' <' . $email . '>',
    'X-Mailer: PHP/' . PHP_VERSION,
];

$mailSent = @mail($recipient, $mailSubject, $mailBody, implode("\r\n", $headers));

if (!$mailSent) {
    respond(500, false, 'Message could not be sent. Configure your server mail settings and try again.');
}

respond(200, true, 'Thanks. Your message has been sent successfully.');
