<?php
// ── Segurança ─────────────────────────────────────────────────────────────
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

// Só aceita POST via fetch (AJAX)
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'erro' => 'Método não permitido.']);
    exit;
}

// ── Config SMTP ───────────────────────────────────────────────────────────
$config_file = __DIR__ . '/smtp_config.php';
if (!file_exists($config_file)) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'erro' => 'Configuração de e-mail não encontrada. Crie smtp_config.php na VPS.']);
    exit;
}
require $config_file;

// ── Coleta e sanitiza campos ──────────────────────────────────────────────
function campo(string $key, bool $required = false): string {
    $val = trim(strip_tags($_POST[$key] ?? ''));
    if ($required && $val === '') return '';
    return $val;
}

$nome     = campo('nome',     true);
$clinica  = campo('clinica',  true);
$email    = campo('email',    true);
$cargo    = campo('cargo');
$estado   = campo('estado');
$telefone = campo('telefone');
$desafio  = campo('desafio');
$mensagem = campo('mensagem');

// Validações básicas
if (!$nome || !$clinica || !$email) {
    echo json_encode(['ok' => false, 'erro' => 'Preencha os campos obrigatórios.']);
    exit;
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(['ok' => false, 'erro' => 'E-mail inválido.']);
    exit;
}

// ── Monta o e-mail ────────────────────────────────────────────────────────
$desafio_label = match($desafio) {
    'faturamento' => 'Faturamento',
    'agenda'      => 'Ociosidade de agenda',
    'processos'   => 'Processos internos',
    'dados'       => 'Gestão de dados',
    'crescimento' => 'Crescimento geral',
    default       => 'Não informado',
};

$assunto = "Novo lead: {$nome} — {$clinica}";

$corpo = "
<html>
<body style='font-family:Arial,sans-serif;color:#333;max-width:600px;margin:0 auto'>
  <div style='background:#18181b;padding:24px 32px;border-radius:8px 8px 0 0'>
    <h2 style='color:#c9a96e;margin:0;font-size:1.3rem'>Novo lead via site PGE</h2>
  </div>
  <div style='background:#f9f9f9;padding:24px 32px;border:1px solid #e4e4e7;border-top:none;border-radius:0 0 8px 8px'>
    <table style='width:100%;border-collapse:collapse'>
      <tr><td style='padding:10px 0;border-bottom:1px solid #e4e4e7;font-weight:700;width:180px'>Nome</td><td style='padding:10px 0;border-bottom:1px solid #e4e4e7'>" . htmlspecialchars($nome) . "</td></tr>
      <tr><td style='padding:10px 0;border-bottom:1px solid #e4e4e7;font-weight:700'>Cargo</td><td style='padding:10px 0;border-bottom:1px solid #e4e4e7'>" . htmlspecialchars($cargo ?: '—') . "</td></tr>
      <tr><td style='padding:10px 0;border-bottom:1px solid #e4e4e7;font-weight:700'>Clínica</td><td style='padding:10px 0;border-bottom:1px solid #e4e4e7'>" . htmlspecialchars($clinica) . "</td></tr>
      <tr><td style='padding:10px 0;border-bottom:1px solid #e4e4e7;font-weight:700'>Estado</td><td style='padding:10px 0;border-bottom:1px solid #e4e4e7'>" . htmlspecialchars($estado ?: '—') . "</td></tr>
      <tr><td style='padding:10px 0;border-bottom:1px solid #e4e4e7;font-weight:700'>E-mail</td><td style='padding:10px 0;border-bottom:1px solid #e4e4e7'><a href='mailto:" . htmlspecialchars($email) . "'>" . htmlspecialchars($email) . "</a></td></tr>
      <tr><td style='padding:10px 0;border-bottom:1px solid #e4e4e7;font-weight:700'>Telefone</td><td style='padding:10px 0;border-bottom:1px solid #e4e4e7'>" . htmlspecialchars($telefone ?: '—') . "</td></tr>
      <tr><td style='padding:10px 0;border-bottom:1px solid #e4e4e7;font-weight:700'>Desafio</td><td style='padding:10px 0;border-bottom:1px solid #e4e4e7'>" . htmlspecialchars($desafio_label) . "</td></tr>
      <tr><td style='padding:10px 0;font-weight:700;vertical-align:top'>Mensagem</td><td style='padding:10px 0'>" . nl2br(htmlspecialchars($mensagem ?: '—')) . "</td></tr>
    </table>
    <p style='margin-top:24px;font-size:12px;color:#9b9b9b'>Enviado em " . date('d/m/Y H:i') . " • Site pgeclinicas.com.br</p>
  </div>
</body>
</html>
";

// ── Envio via SMTP nativo ─────────────────────────────────────────────────
function smtp_send(string $host, int $port, string $user, string $pass, string $from, string $from_name, string $to, string $subject, string $body): bool|string
{
    $errno = $errstr = null;
    $prefix = $port === 465 ? 'ssl://' : '';
    $socket = @fsockopen("{$prefix}{$host}", $port, $errno, $errstr, 10);
    if (!$socket) return "Conexão falhou: {$errstr}";

    $read = fn() => fgets($socket, 1024);
    $send = function(string $cmd) use ($socket, $read) {
        fwrite($socket, $cmd . "\r\n");
        return $read();
    };

    $read(); // banner
    $send("EHLO pgeclinicas.com.br");
    $read(); $read(); $read(); $read(); $read(); // multi-line EHLO

    if ($port === 587) {
        $send("STARTTLS");
        $read();
        stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
        $send("EHLO pgeclinicas.com.br");
        $read(); $read(); $read(); $read(); $read();
    }

    $send("AUTH LOGIN");
    $read();
    $send(base64_encode($user));
    $read();
    $send(base64_encode($pass));
    $auth = $read();
    if (!str_starts_with($auth, '235')) {
        fclose($socket);
        return "Autenticação falhou: {$auth}";
    }

    $send("MAIL FROM:<{$from}>");  $read();
    $send("RCPT TO:<{$to}>");      $read();
    $send("DATA");                  $read();

    $boundary = md5(uniqid());
    $headers = implode("\r\n", [
        "From: {$from_name} <{$from}>",
        "To: {$to}",
        "Reply-To: {$from_name} <{$from}>",
        "Subject: =?UTF-8?B?" . base64_encode($subject) . "?=",
        "MIME-Version: 1.0",
        "Content-Type: text/html; charset=UTF-8",
        "X-Mailer: PGE-Site/1.0",
    ]);

    fwrite($socket, $headers . "\r\n\r\n" . $body . "\r\n.\r\n");
    $resp = $read();
    $send("QUIT");
    fclose($socket);

    return str_starts_with($resp, '250') ? true : "Erro ao enviar: {$resp}";
}

// ── Envio via Webhook (opcional) ──────────────────────────────────────────
$webhook_ok = true;
if (defined('WEBHOOK_URL') && !empty(WEBHOOK_URL)) {
    $payload = json_encode([
        'nome'     => $nome,
        'clinica'  => $clinica,
        'email'    => $email,
        'cargo'    => $cargo,
        'estado'   => $estado,
        'telefone' => $telefone,
        'desafio'  => $desafio_label,
        'mensagem' => $mensagem,
        'data'     => date('Y-m-d H:i:s'),
        'origem'   => 'site-pge',
        'site-pge' => true
    ]);

    $ch = curl_init(WEBHOOK_URL);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'Content-Length: ' . strlen($payload)
    ]);
    curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($http_code < 200 || $http_code >= 300) {
        $webhook_ok = false;
        error_log("contato.php Webhook error: HTTP {$http_code}");
    }
}

$resultado = true;
// Só tenta enviar e-mail se as constantes SMTP foram configuradas com valores reais
if (defined('SMTP_HOST') && SMTP_HOST !== 'mail.seudominio.com.br' && !empty(SMTP_HOST)) {
    $resultado = smtp_send(
        SMTP_HOST, SMTP_PORT,
        SMTP_USER, SMTP_PASS,
        SMTP_FROM, SMTP_NAME,
        MAIL_TO,
        $assunto,
        $corpo
    );
}

if ($resultado === true || $webhook_ok === true) {
    echo json_encode(['ok' => true]);
} else {
    error_log("contato.php SMTP error: {$resultado}");
    http_response_code(500);
    echo json_encode(['ok' => false, 'erro' => 'Não foi possível processar o envio. Tente novamente mais tarde.']);
}
