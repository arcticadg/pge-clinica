<?php
// ── Security Headers ──────────────────────────────────────────────────────────
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Content-Security-Policy: default-src \'self\'; style-src \'self\' \'unsafe-inline\'; script-src \'self\' \'unsafe-inline\'');

// ── Constantes ────────────────────────────────────────────────────────────────
define('PGE_ADMIN',       true);
define('CRED_FILE',       __DIR__ . '/credentials.php');
define('CONFIG_FILE',     __DIR__ . '/config.json');
define('UPLOAD_DIR',      __DIR__ . '/uploads/');
define('RATE_FILE',       __DIR__ . '/rate_limit.json');
define('MAX_ATTEMPTS',    5);
define('LOCKOUT_SECS',    900);   // 15 minutos
define('SESSION_TIMEOUT', 1800);  // 30 minutos

session_start();

// ── CSRF ──────────────────────────────────────────────────────────────────────
function csrf_token(): string {
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}
function csrf_check(): void {
    if (!isset($_SESSION['csrf']) || !hash_equals($_SESSION['csrf'], $_POST['csrf'] ?? '')) {
        http_response_code(403);
        die('Requisição inválida. Volte e tente novamente.');
    }
}

// ── Rate Limit (por IP, baseado em arquivo) ───────────────────────────────────
function rl_get(): array {
    if (!file_exists(RATE_FILE)) return [];
    $d = json_decode(file_get_contents(RATE_FILE), true);
    return is_array($d) ? $d : [];
}
function rl_save(array $d): void { file_put_contents(RATE_FILE, json_encode($d)); }
function rl_check(): ?string {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0';
    $d  = rl_get();
    if (!isset($d[$ip])) return null;
    $e  = $d[$ip];
    if ($e['attempts'] >= MAX_ATTEMPTS) {
        $rem = LOCKOUT_SECS - (time() - $e['ts']);
        if ($rem > 0) return 'Muitas tentativas. Aguarde ' . ceil($rem / 60) . ' min.';
        unset($d[$ip]); rl_save($d);
    }
    return null;
}
function rl_fail(): void {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0';
    $d  = rl_get();
    if (!isset($d[$ip]) || (time() - $d[$ip]['ts']) > LOCKOUT_SECS) {
        $d[$ip] = ['attempts' => 0, 'ts' => time()];
    }
    $d[$ip]['attempts']++;
    $d[$ip]['ts'] = time();
    rl_save($d);
}
function rl_clear(): void {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0';
    $d  = rl_get(); unset($d[$ip]); rl_save($d);
}

// ── Timeout de sessão ─────────────────────────────────────────────────────────
if (!empty($_SESSION['logado'])) {
    if (isset($_SESSION['last']) && (time() - $_SESSION['last']) > SESSION_TIMEOUT) {
        session_destroy();
        header('Location: admin.php?timeout=1'); exit;
    }
    $_SESSION['last'] = time();
}

// ── Logout ────────────────────────────────────────────────────────────────────
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: admin.php'); exit;
}

// ── Modo Setup (primeira execução — sem credentials.php) ──────────────────────
$setup_mode = !file_exists(CRED_FILE);

if ($setup_mode) {
    $setup_erro = null;
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['setup'])) {
        csrf_check();
        $email  = filter_var(trim($_POST['email'] ?? ''), FILTER_VALIDATE_EMAIL);
        $senha  = $_POST['senha'] ?? '';
        $conf   = $_POST['confirmar'] ?? '';
        if (!$email)              $setup_erro = 'E-mail inválido.';
        elseif (strlen($senha) < 10) $setup_erro = 'A senha deve ter no mínimo 10 caracteres.';
        elseif ($senha !== $conf) $setup_erro = 'As senhas não coincidem.';
        else {
            $hash = password_hash($senha, PASSWORD_BCRYPT, ['cost' => 12]);
            $php  = "<?php\ndefined('PGE_ADMIN') or die('Acesso negado.');\n"
                  . "\$ADMIN_EMAIL = " . var_export($email, true) . ";\n"
                  . "\$ADMIN_HASH  = " . var_export($hash,  true) . ";\n";
            if (file_put_contents(CRED_FILE, $php) === false) {
                $setup_erro = 'Erro: o servidor não tem permissão para gravar credentials.php. Acesse a VPS e rode: chmod 755 ' . escapeshellcmd(__DIR__);
            } else {
                header('Location: admin.php?setup_ok=1'); exit;
            }
        }
    }
    // Exibe form de setup
    ?><!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Configuração Inicial — PGE Admin</title>
<style>
body{font-family:'Segoe UI',sans-serif;background:#f4f4f5;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.box{background:#fff;padding:48px 40px;border-radius:14px;box-shadow:0 4px 28px rgba(0,0,0,.08);width:100%;max-width:380px}
h2{margin:0 0 6px;color:#18181b;font-size:1.3rem}
p.sub{margin:0 0 28px;font-size:.85rem;color:#71717a}
label{display:block;font-size:.8rem;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:#52525b;margin-bottom:6px}
.input{width:100%;padding:12px 14px;border:1.5px solid #e4e4e7;border-radius:9px;font-size:.95rem;box-sizing:border-box;transition:border-color .2s}
.input:focus{outline:none;border-color:#c9a96e}
.group{margin-bottom:20px}
.btn{width:100%;padding:13px;background:#18181b;color:#fff;border:none;border-radius:9px;font-weight:700;font-size:.95rem;cursor:pointer;transition:background .2s;margin-top:4px}
.btn:hover{background:#c9a96e;color:#18181b}
.error{background:#fee2e2;color:#991b1b;border:1px solid #fecaca;padding:10px 14px;border-radius:8px;font-size:.85rem;margin-bottom:20px}
.badge{display:inline-block;background:#dcfce7;color:#166534;font-size:.75rem;font-weight:700;padding:4px 10px;border-radius:999px;margin-bottom:20px}
</style></head><body>
<div class="box">
    <span class="badge">⚙️ Configuração única</span>
    <h2>Criar credenciais de acesso</h2>
    <p class="sub">Este formulário aparece apenas na primeira execução.</p>
    <?php if ($setup_erro): ?><div class="error"><?= htmlspecialchars($setup_erro) ?></div><?php endif ?>
    <?php if (isset($_GET['setup_ok'])): ?><div style="background:#dcfce7;color:#166534;padding:10px 14px;border-radius:8px;font-size:.85rem;margin-bottom:20px">Credenciais salvas! Faça login abaixo.</div><?php endif ?>
    <form method="post">
        <input type="hidden" name="csrf" value="<?= csrf_token() ?>">
        <input type="hidden" name="setup" value="1">
        <div class="group"><label>E-mail de acesso</label><input type="email" name="email" class="input" required autofocus></div>
        <div class="group"><label>Senha (mín. 10 caracteres)</label><input type="password" name="senha" class="input" required></div>
        <div class="group"><label>Confirmar senha</label><input type="password" name="confirmar" class="input" required></div>
        <button type="submit" class="btn">Salvar e entrar</button>
    </form>
</div>
</body></html>
    <?php exit;
}

// ── Carrega credenciais ───────────────────────────────────────────────────────
require CRED_FILE;

// ── Processa Login ────────────────────────────────────────────────────────────
$erro_login = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    csrf_check();
    $rate_err = rl_check();
    if ($rate_err) {
        $erro_login = $rate_err;
    } else {
        $email_in = trim($_POST['email'] ?? '');
        $senha_in = $_POST['senha'] ?? '';
        if ($email_in === $ADMIN_EMAIL && password_verify($senha_in, $ADMIN_HASH)) {
            rl_clear();
            session_regenerate_id(true);
            $_SESSION['logado'] = true;
            $_SESSION['last']   = time();
            header('Location: admin.php'); exit;
        } else {
            rl_fail();
            $erro_login = 'E-mail ou senha incorretos.';
        }
    }
}

// ── Guard ─────────────────────────────────────────────────────────────────────
if (empty($_SESSION['logado'])) {
    ?><!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Acesso Restrito — PGE</title>
<style>
body{font-family:'Segoe UI',sans-serif;background:#f4f4f5;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.box{background:#fff;padding:48px 40px;border-radius:14px;box-shadow:0 4px 28px rgba(0,0,0,.08);width:100%;max-width:360px;text-align:center}
.logo{font-size:1.5rem;font-weight:800;letter-spacing:.04em;color:#18181b;margin-bottom:4px}.logo span{color:#c9a96e}
.sub{font-size:.82rem;color:#71717a;margin-bottom:32px}
label{display:block;font-size:.78rem;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:#52525b;margin-bottom:6px;text-align:left}
.input{width:100%;padding:12px 14px;border:1.5px solid #e4e4e7;border-radius:9px;font-size:.95rem;box-sizing:border-box;transition:border-color .2s}
.input:focus{outline:none;border-color:#c9a96e}
.group{margin-bottom:18px;text-align:left}
.btn{width:100%;padding:13px;background:#18181b;color:#fff;border:none;border-radius:9px;font-weight:700;font-size:.95rem;cursor:pointer;transition:background .2s;margin-top:6px}
.btn:hover{background:#c9a96e;color:#18181b}
.error{background:#fee2e2;color:#991b1b;border:1px solid #fecaca;padding:10px 14px;border-radius:8px;font-size:.85rem;margin-bottom:20px;text-align:left}
.timeout{background:#fef9c3;color:#713f12;border:1px solid #fde68a;padding:10px 14px;border-radius:8px;font-size:.85rem;margin-bottom:20px;text-align:left}
</style></head><body>
<div class="box">
    <div class="logo">PG<span>E</span></div>
    <p class="sub">Painel Gerencial — Acesso Restrito</p>
    <?php if (isset($_GET['timeout'])): ?><div class="timeout">Sessão encerrada por inatividade.</div><?php endif ?>
    <?php if ($erro_login): ?><div class="error"><?= htmlspecialchars($erro_login) ?></div><?php endif ?>
    <form method="post">
        <input type="hidden" name="csrf" value="<?= csrf_token() ?>">
        <input type="hidden" name="login" value="1">
        <div class="group"><label>E-mail</label><input type="email" name="email" class="input" required autofocus autocomplete="username"></div>
        <div class="group"><label>Senha</label><input type="password" name="senha" class="input" required autocomplete="current-password"></div>
        <button type="submit" class="btn">Entrar</button>
    </form>
</div>
</body></html>
    <?php exit;
}

// ═════════════════════════════════════════════════════════════════════════════
//  ÁREA AUTENTICADA
// ═════════════════════════════════════════════════════════════════════════════

if (!is_dir(UPLOAD_DIR)) mkdir(UPLOAD_DIR, 0755, true);

$dados = ['whatsapp_number' => '', 'whatsapp_message' => '', 'units' => []];
if (file_exists(CONFIG_FILE)) {
    $cur = json_decode(file_get_contents(CONFIG_FILE), true);
    if (is_array($cur)) $dados = array_merge($dados, $cur);
}

$aba_ativa = $_GET['tab'] ?? 'unidades';
$msg_sucesso = $msg_erro = null;

// Salvar CTA
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['salvar_cta'])) {
    csrf_check();
    $dados['whatsapp_number']  = trim($_POST['whatsapp_number']);
    $dados['whatsapp_message'] = trim($_POST['whatsapp_message']);
    if (file_put_contents(CONFIG_FILE, json_encode($dados, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)))
        $msg_sucesso = 'Configurações de CTA salvas com sucesso!';
    else $msg_erro = 'Erro ao salvar config.json.';
    $aba_ativa = 'cta';
}

// Salvar Unidade
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['salvar_unidade'])) {
    csrf_check();
    $unidade = [
        'id'      => uniqid(),
        'name'    => trim($_POST['nome_unidade']),
        'state'   => trim($_POST['estado_unidade']),
        'phone'   => trim($_POST['telefone_unidade'] ?? ''),
        'address' => trim($_POST['endereco_unidade']),
        'logo'    => '',
    ];
    if (isset($_FILES['logo_unidade']) && $_FILES['logo_unidade']['error'] === UPLOAD_ERR_OK) {
        $ext     = strtolower(pathinfo($_FILES['logo_unidade']['name'], PATHINFO_EXTENSION));
        $allowed = ['jpg','jpeg','png','svg','webp'];
        if (in_array($ext, $allowed)) {
            $dest = UPLOAD_DIR . uniqid('logo_') . '.' . $ext;
            if (move_uploaded_file($_FILES['logo_unidade']['tmp_name'], $dest))
                $unidade['logo'] = $dest;
        } else {
            $msg_erro = 'Formato inválido (use PNG, JPG, SVG ou WebP).';
        }
    }
    if (!$msg_erro) {
        $dados['units'][] = $unidade;
        if (file_put_contents(CONFIG_FILE, json_encode($dados, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)))
            $msg_sucesso = 'Clínica cadastrada com sucesso!';
        else $msg_erro = 'Erro ao salvar config.json.';
    }
    $aba_ativa = 'unidades';
}

// Excluir Unidade
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['excluir_unidade_id'])) {
    csrf_check();
    foreach ($dados['units'] as $k => $u) {
        if ($u['id'] === $_POST['excluir_unidade_id']) {
            if (!empty($u['logo']) && file_exists($u['logo'])) unlink($u['logo']);
            unset($dados['units'][$k]);
            $msg_sucesso = 'Unidade excluída.';
            break;
        }
    }
    $dados['units'] = array_values($dados['units']);
    file_put_contents(CONFIG_FILE, json_encode($dados, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    $aba_ativa = 'unidades';
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Painel Gerencial — PGE</title>
<style>
:root{--bg:#f4f4f5;--box:#fff;--text:#18181b;--muted:#71717a;--border:#e4e4e7;--primary:#18181b;--gold:#c9a96e}
body{font-family:'Segoe UI',sans-serif;background:var(--bg);color:var(--text);margin:0;padding:40px 20px}
.wrap{max-width:840px;margin:0 auto;background:var(--box);padding:40px;border-radius:14px;box-shadow:0 4px 28px rgba(0,0,0,.07)}
.hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:32px;border-bottom:1px solid var(--border);padding-bottom:20px}
.hdr h1{margin:0;font-size:1.4rem}.logout{color:#ef4444;text-decoration:none;font-weight:600;font-size:.88rem}
.tabs{display:flex;border-bottom:1px solid var(--border);margin-bottom:28px}
.tab-btn{background:none;border:none;padding:11px 22px;font-size:.93rem;font-weight:600;color:var(--muted);cursor:pointer;border-bottom:2.5px solid transparent;margin-bottom:-1px;transition:all .2s}
.tab-btn:hover{color:var(--primary)}.tab-btn.active{color:var(--primary);border-bottom-color:var(--gold)}
.tab-content{display:none}.tab-content.active{display:block}
.group{margin-bottom:22px}
.group label{display:block;font-weight:700;font-size:.8rem;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);margin-bottom:7px}
.group .hint{font-size:.8rem;color:var(--muted);margin-bottom:7px;display:block}
.input{width:100%;padding:11px 14px;border:1.5px solid var(--border);border-radius:9px;font-size:.93rem;font-family:inherit;box-sizing:border-box;transition:border-color .2s}
.input:focus{outline:none;border-color:var(--gold)}
.btn{padding:11px 24px;background:var(--primary);color:#fff;border:none;border-radius:9px;font-weight:700;cursor:pointer;transition:background .2s;font-size:.93rem}
.btn:hover{background:var(--gold);color:var(--primary)}
.btn-danger{background:#fee2e2;color:#991b1b;padding:8px 14px;font-size:.82rem;border-radius:7px;border:none;cursor:pointer;font-weight:700}
.btn-danger:hover{background:#fecaca}
.alert{padding:12px 16px;border-radius:9px;margin-bottom:22px;font-size:.88rem}
.ok{background:#dcfce7;color:#166534;border:1px solid #bbf7d0}
.err{background:#fee2e2;color:#991b1b;border:1px solid #fecaca}
.table-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:9px;margin-top:28px}
table{width:100%;border-collapse:collapse;text-align:left}
th,td{padding:15px 16px;border-bottom:1px solid var(--border)}
th{background:#fafafa;font-size:.8rem;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:none}
.logo-preview{height:38px;width:38px;object-fit:contain;border-radius:5px;border:1px solid var(--border);padding:3px}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.sub-box{background:#fafafa;padding:24px;border-radius:9px;border:1px solid var(--border);margin-bottom:24px}
.sub-box h3{margin-top:0;font-size:1rem}
.session-info{font-size:.78rem;color:var(--muted);text-align:right;margin-bottom:24px}
</style>
</head>
<body>
<div class="wrap">
    <div class="hdr">
        <h1>🔧 Painel PGE</h1>
        <div style="display:flex;align-items:center;gap:24px">
            <span class="session-info" style="margin:0">Sessão expira em 30 min de inatividade</span>
            <a href="?logout=1" class="logout">Sair</a>
        </div>
    </div>

    <?php if ($msg_sucesso): ?><div class="alert ok"><?= htmlspecialchars($msg_sucesso) ?></div><?php endif ?>
    <?php if ($msg_erro):    ?><div class="alert err"><?= htmlspecialchars($msg_erro) ?></div><?php endif ?>

    <div class="tabs">
        <button class="tab-btn <?= $aba_ativa === 'unidades' ? 'active' : '' ?>" onclick="switchTab('unidades')">Unidades (Clínicas)</button>
        <button class="tab-btn <?= $aba_ativa === 'cta'      ? 'active' : '' ?>" onclick="switchTab('cta')">WhatsApp / CTA</button>
    </div>

    <!-- ABA: UNIDADES -->
    <div id="tab-unidades" class="tab-content <?= $aba_ativa === 'unidades' ? 'active' : '' ?>">
        <div class="sub-box">
            <h3>Adicionar Nova Clínica</h3>
            <form method="post" enctype="multipart/form-data">
                <input type="hidden" name="csrf" value="<?= csrf_token() ?>">
                <div class="grid-2">
                    <div class="group"><label>Nome da Clínica</label><input type="text" name="nome_unidade" class="input" required placeholder="Ex: Clínica MedMais"></div>
                    <div class="group"><label>Telefone / WhatsApp</label><input type="text" name="telefone_unidade" class="input" placeholder="Ex: (11) 90000-0000"></div>
                </div>
                <div class="grid-2">
                    <div class="group"><label>Endereço Completo</label><input type="text" name="endereco_unidade" class="input" required placeholder="Ex: Av. Paulista, 1000 — SP"></div>
                    <div class="group"><label>Estado</label>
                        <select name="estado_unidade" class="input" required>
                            <option value="">Selecione...</option>
                            <?php foreach(['AC'=>'Acre','AL'=>'Alagoas','AP'=>'Amapá','AM'=>'Amazonas','BA'=>'Bahia','CE'=>'Ceará','DF'=>'Distrito Federal','ES'=>'Espírito Santo','GO'=>'Goiás','MA'=>'Maranhão','MT'=>'Mato Grosso','MS'=>'Mato Grosso do Sul','MG'=>'Minas Gerais','PA'=>'Pará','PB'=>'Paraíba','PR'=>'Paraná','PE'=>'Pernambuco','PI'=>'Piauí','RJ'=>'Rio de Janeiro','RN'=>'Rio Grande do Norte','RS'=>'Rio Grande do Sul','RO'=>'Rondônia','RR'=>'Roraima','SC'=>'Santa Catarina','SP'=>'São Paulo','SE'=>'Sergipe','TO'=>'Tocantins'] as $uf => $nome): ?>
                            <option value="<?= $uf ?>"><?= $nome ?></option>
                            <?php endforeach ?>
                        </select>
                    </div>
                </div>
                <div class="group"><label>Logomarca (opcional)</label><input type="file" name="logo_unidade" class="input" accept="image/*"></div>
                <button type="submit" name="salvar_unidade" class="btn">Cadastrar Clínica</button>
            </form>
        </div>

        <div class="table-wrap">
            <table>
                <thead><tr><th>Logo</th><th>Clínica / Endereço</th><th>UF</th><th>Ação</th></tr></thead>
                <tbody>
                <?php if (empty($dados['units'])): ?>
                    <tr><td colspan="4" style="text-align:center;color:var(--muted)">Nenhuma unidade cadastrada.</td></tr>
                <?php else: ?>
                    <?php foreach ($dados['units'] as $u): ?>
                    <tr>
                        <td><?= !empty($u['logo']) ? '<img src="' . htmlspecialchars($u['logo']) . '" class="logo-preview" alt="Logo">' : '—' ?></td>
                        <td><strong><?= htmlspecialchars($u['name']) ?></strong><br><span style="font-size:.8rem;color:var(--muted)"><?= htmlspecialchars($u['address']) ?></span></td>
                        <td><span style="background:var(--bg);padding:3px 8px;border-radius:5px;font-size:.8rem;font-weight:700"><?= htmlspecialchars($u['state']) ?></span></td>
                        <td>
                            <form method="post" style="display:inline" onsubmit="return confirm('Remover esta unidade?')">
                                <input type="hidden" name="csrf" value="<?= csrf_token() ?>">
                                <input type="hidden" name="excluir_unidade_id" value="<?= $u['id'] ?>">
                                <button type="submit" class="btn-danger">Excluir</button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach ?>
                <?php endif ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- ABA: CTA -->
    <div id="tab-cta" class="tab-content <?= $aba_ativa === 'cta' ? 'active' : '' ?>">
        <form method="post">
            <input type="hidden" name="csrf" value="<?= csrf_token() ?>">
            <div class="group">
                <label>Número do WhatsApp</label>
                <span class="hint">Apenas números + DDI (55) + DDD. Ex: 5511999999999</span>
                <input type="text" name="whatsapp_number" class="input" value="<?= htmlspecialchars($dados['whatsapp_number'] ?? '') ?>" required>
            </div>
            <div class="group">
                <label>Mensagem padrão do CTA</label>
                <span class="hint">Texto enviado pelo visitante ao abrir o WhatsApp.</span>
                <input type="text" name="whatsapp_message" class="input" value="<?= htmlspecialchars($dados['whatsapp_message'] ?? '') ?>">
            </div>
            <button type="submit" name="salvar_cta" class="btn">Salvar Configurações</button>
        </form>
    </div>
</div>

<script>
function switchTab(id) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    event.target.classList.add('active');
    document.getElementById('tab-' + id).classList.add('active');
    history.replaceState(null, '', '?tab=' + id);
}
</script>
</body>
</html>
