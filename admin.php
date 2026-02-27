<?php
// admin.php - Painel de Controle Avançado

// --- CONFIGURAÇÕES DE SEGURANÇA ---
$SENHA_ADMIN = 'pge2025admin';
$configFile = 'config.json';
$uploadDir = 'uploads/';

session_start();

// Logout
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: admin.php");
    exit;
}

// Login Process
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    if ($_POST['senha'] === $SENHA_ADMIN) {
        $_SESSION['logado'] = true;
    } else {
        $erro_login = "Senha incorreta!";
    }
}

// Verifica Autenticação
if (!isset($_SESSION['logado']) || $_SESSION['logado'] !== true) {
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Painel Admin - PGE</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f4f5; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .login-box { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 24px rgba(0,0,0,0.06); text-align: center; width: 100%; max-width: 320px; }
        .login-box h2 { margin: 0 0 24px; color: #18181b; }
        .input { width: 100%; padding: 12px 16px; margin-bottom: 16px; border: 1px solid #e4e4e7; border-radius: 8px; font-size: 16px; box-sizing: border-box; }
        .btn { width: 100%; padding: 12px; background: #18181b; color: white; border: none; border-radius: 8px; font-weight: bold; cursor: pointer; transition: background 0.2s; }
        .btn:hover { background: #c9a96e; color: #18181b; }
        .error { color: #ef4444; margin-bottom: 16px; font-size: 14px; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Acesso Restrito</h2>
        <?php if(isset($erro_login)) echo "<p class='error'>$erro_login</p>"; ?>
        <form method="post">
            <input type="password" name="senha" class="input" placeholder="Digite a senha" required autofocus>
            <button type="submit" name="login" class="btn">Entrar</button>
        </form>
    </div>
</body>
</html>
<?php
    exit;
}

// Helper: Ensure Upload Dir exists
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0755, true);
}

// Ler Dados Atuais
$dados = ["whatsapp_number" => "", "whatsapp_message" => "", "units" => []];
if (file_exists($configFile)) {
    $current = json_decode(file_get_contents($configFile), true);
    if(is_array($current)) {
        $dados = array_merge($dados, $current);
    }
}

$aba_ativa = $_GET['tab'] ?? 'unidades';

// Salvar CTA
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['salvar_cta'])) {
    $dados['whatsapp_number'] = trim($_POST['whatsapp_number']);
    $dados['whatsapp_message'] = trim($_POST['whatsapp_message']);
    
    if (file_put_contents($configFile, json_encode($dados, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE))) {
        $msg_sucesso = "Configurações de CTA salvas com sucesso!";
    } else {
        $msg_erro = "Erro ao salvar arquivo config.json.";
    }
    $aba_ativa = 'cta';
}

// Salvar Nova Unidade
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['salvar_unidade'])) {
    $unidade = [
        "id" => uniqid(),
        "name" => trim($_POST['nome_unidade']),
        "state" => trim($_POST['estado_unidade']),
        "phone" => trim($_POST['telefone_unidade'] ?? ''),
        "address" => trim($_POST['endereco_unidade']),
        "logo" => ""
    ];

    // Tratar Upload (Opcional)
    if (isset($_FILES['logo_unidade']) && $_FILES['logo_unidade']['error'] === UPLOAD_ERR_OK) {
        $ext = strtolower(pathinfo($_FILES['logo_unidade']['name'], PATHINFO_EXTENSION));
        $allowed = ['jpg', 'jpeg', 'png', 'svg', 'webp'];
        if (in_array($ext, $allowed)) {
            $filename = uniqid('logo_') . '.' . $ext;
            $dest = $uploadDir . $filename;
            if (move_uploaded_file($_FILES['logo_unidade']['tmp_name'], $dest)) {
                $unidade['logo'] = escapeshellcmd($dest); // Caminho relativo salvo no JSON
            }
        } else {
            $msg_erro = "Formato de imagem inválido (Use PNG, JPG, ou SVG).";
        }
    }

    if (!isset($msg_erro)) {
        if (!isset($dados['units'])) {
            $dados['units'] = [];
        }
        $dados['units'][] = $unidade;

        if (file_put_contents($configFile, json_encode($dados, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE))) {
            $msg_sucesso = "Unidade cadastrada com sucesso!";
        } else {
            $msg_erro = "Erro ao salvar config.json.";
        }
    }
    $aba_ativa = 'unidades';
}

// Excluir Unidade
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['excluir_unidade_id'])) {
    $del_id = $_POST['excluir_unidade_id'];
    foreach ($dados['units'] as $k => $u) {
        if ($u['id'] === $del_id) {
            // Remove o arquivo físico se existir
            if (!empty($u['logo']) && file_exists($u['logo'])) {
                unlink($u['logo']);
            }
            unset($dados['units'][$k]);
            $msg_sucesso = "Unidade excluída com sucesso!";
            break;
        }
    }
    // Reindexar array
    $dados['units'] = array_values($dados['units']);
    file_put_contents($configFile, json_encode($dados, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    $aba_ativa = 'unidades';
}
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Painel Gerencial - PGE</title>
    <style>
        :root { --bg: #f4f4f5; --box: #ffffff; --text: #18181b; --text-muted: #71717a; --border: #e4e4e7; --primary: #18181b; --gold: #c9a96e; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 40px 20px; }
        .container { max-width: 800px; margin: 0 auto; background: var(--box); padding: 40px; border-radius: 12px; box-shadow: 0 4px 24px rgba(0,0,0,0.06); }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 32px; border-bottom: 1px solid var(--border); padding-bottom: 20px; }
        .header h1 { margin: 0; font-size: 1.5rem; }
        .logout { color: #ef4444; text-decoration: none; font-weight: 500; font-size: 14px; }
        
        /* Tabs */
        .tabs { display: flex; border-bottom: 1px solid var(--border); margin-bottom: 24px; }
        .tab-btn { background: none; border: none; padding: 12px 24px; font-size: 15px; font-weight: 600; color: var(--text-muted); cursor: pointer; border-bottom: 2px solid transparent; margin-bottom: -1px; transition: all 0.2s; }
        .tab-btn:hover { color: var(--primary); }
        .tab-btn.active { color: var(--primary); border-bottom-color: var(--gold); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }

        .form-group { margin-bottom: 24px; }
        .form-group label { display: block; font-weight: 600; margin-bottom: 8px; font-size: 14px; }
        .form-group .hint { display: block; font-size: 13px; color: var(--text-muted); margin-bottom: 8px; }
        .input { width: 100%; padding: 12px 16px; border: 1px solid var(--border); border-radius: 8px; font-size: 15px; font-family: inherit; box-sizing: border-box; }
        .input:focus { outline: none; border-color: var(--gold); }
        
        .btn { padding: 12px 24px; background: var(--primary); color: white; border: none; border-radius: 8px; font-weight: bold; cursor: pointer; transition: background 0.2s; font-size: 15px; }
        .btn:hover { background: var(--gold); color: var(--primary); }

        .btn-danger { background: #fee2e2; color: #991b1b; padding: 8px 16px; font-size: 13px; border-radius: 6px; }
        .btn-danger:hover { background: #fecaca; }
        
        .alert { padding: 12px; border-radius: 8px; margin-bottom: 24px; font-size: 14px; }
        .alert-success { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }
        .alert-error { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }

        /* Table */
        .table-wrap { overflow-x: auto; margin-top: 32px; border: 1px solid var(--border); border-radius: 8px; }
        table { width: 100%; border-collapse: collapse; text-align: left; }
        th, td { padding: 16px; border-bottom: 1px solid var(--border); }
        th { background: #fafafa; font-size: 14px; color: var(--text-muted); font-weight: 600; }
        tr:last-child td { border-bottom: none; }
        .logo-preview { height: 40px; width: 40px; object-fit: contain; border-radius: 4px; background: #fff; border: 1px solid var(--border); padding: 4px; }
        
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    </style>
</head>
<body>

<div class="container">
    <div class="header">
        <h1>🔧 Gerenciar Site PGE</h1>
        <a href="?logout=1" class="logout">Sair</a>
    </div>

    <?php if(isset($msg_sucesso)) echo "<div class='alert alert-success'>$msg_sucesso</div>"; ?>
    <?php if(isset($msg_erro)) echo "<div class='alert alert-error'>$msg_erro</div>"; ?>

    <div class="tabs">
        <button class="tab-btn <?= $aba_ativa === 'unidades' ? 'active' : '' ?>" onclick="switchTab('unidades')">Unidades (Clínicas)</button>
        <button class="tab-btn <?= $aba_ativa === 'cta' ? 'active' : '' ?>" onclick="switchTab('cta')">Configuração CTA (WhatsApp)</button>
    </div>

    <!-- ABA: UNIDADES -->
    <div id="tab-unidades" class="tab-content <?= $aba_ativa === 'unidades' ? 'active' : '' ?>">   
        <div style="background: #fafafa; padding: 24px; border-radius: 8px; border: 1px solid var(--border); margin-bottom: 24px;">
            <h3 style="margin-top:0;">Adicionar Nova Clínica</h3>
            <form method="post" enctype="multipart/form-data">
                <div class="grid-2">
                    <div class="form-group">
                        <label>Nome da Clínica</label>
                        <input type="text" name="nome_unidade" class="input" required placeholder="Ex: Clínica MedMais">
                    </div>
                    <div class="form-group">
                        <label>Telefone / WhatsApp (Opcional)</label>
                        <input type="text" name="telefone_unidade" class="input" placeholder="Ex: (11) 90000-0000">
                    </div>
                </div>
                <div class="grid-2">
                    <div class="form-group">
                        <label>Endereço Completo</label>
                        <input type="text" name="endereco_unidade" class="input" required placeholder="Ex: Av. Paulista, 1000 - São Paulo, SP">
                    </div>
                    <div class="form-group">
                        <label>Estado da Federação</label>
                        <select name="estado_unidade" class="input" required>
                            <option value="">Selecione...</option>
                            <option value="AC">Acre</option>
                            <option value="AL">Alagoas</option>
                            <option value="AP">Amapá</option>
                            <option value="AM">Amazonas</option>
                            <option value="BA">Bahia</option>
                            <option value="CE">Ceará</option>
                            <option value="DF">Distrito Federal</option>
                            <option value="ES">Espírito Santo</option>
                            <option value="GO">Goiás</option>
                            <option value="MA">Maranhão</option>
                            <option value="MT">Mato Grosso</option>
                            <option value="MS">Mato Grosso do Sul</option>
                            <option value="MG">Minas Gerais</option>
                            <option value="PA">Pará</option>
                            <option value="PB">Paraíba</option>
                            <option value="PR">Paraná</option>
                            <option value="PE">Pernambuco</option>
                            <option value="PI">Piauí</option>
                            <option value="RJ">Rio de Janeiro</option>
                            <option value="RN">Rio Grande do Norte</option>
                            <option value="RS">Rio Grande do Sul</option>
                            <option value="RO">Rondônia</option>
                            <option value="RR">Roraima</option>
                            <option value="SC">Santa Catarina</option>
                            <option value="SP">São Paulo</option>
                            <option value="SE">Sergipe</option>
                            <option value="TO">Tocantins</option>
                        </select>
                    </div>
                </div>
                <div class="form-group">
                    <label>Logomarca da Clínica (Opcional)</label>
                    <input type="file" name="logo_unidade" class="input" accept="image/*">
                </div>
                <button type="submit" name="salvar_unidade" class="btn">Cadastrar Clínica</button>
            </form>
        </div>

        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Logo</th>
                        <th>Clínica</th>
                        <th>Estado</th>
                        <th>Ações</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($dados['units'])): ?>
                        <tr><td colspan="4" style="text-align:center;color:var(--text-muted);">Nenhuma unidade cadastrada.</td></tr>
                    <?php else: ?>
                        <?php foreach($dados['units'] as $u): ?>
                        <tr>
                            <td>
                                <?php if (!empty($u['logo'])): ?>
                                    <img src="<?= htmlspecialchars($u['logo']) ?>" class="logo-preview" alt="Logo">
                                <?php else: ?>
                                    -
                                <?php endif; ?>
                            </td>
                            <td>
                                <strong><?= htmlspecialchars($u['name']) ?></strong><br>
                                <span style="font-size:12px;color:var(--text-muted);"><?= htmlspecialchars($u['address']) ?></span>
                            </td>
                            <td><span style="background:var(--bg);padding:4px 8px;border-radius:4px;font-size:12px;font-weight:600;"><?= htmlspecialchars($u['state']) ?></span></td>
                            <td>
                                <form method="post" style="display:inline;" onsubmit="return confirm('Tem certeza que deseja remover esta unidade?');">
                                    <input type="hidden" name="excluir_unidade_id" value="<?= $u['id'] ?>">
                                    <button type="submit" class="btn btn-danger">Excluir</button>
                                </form>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- ABA: CTA (WhatsApp) -->
    <div id="tab-cta" class="tab-content <?= $aba_ativa === 'cta' ? 'active' : '' ?>">
        <form method="post">
            <div class="form-group">
                <label for="whatsapp_number">Número do WhatsApp (PGE Central)</label>
                <span class="hint">Apenas números, inclua o DDI (55) e o DDD. Ex: 5511999999999</span>
                <input type="text" id="whatsapp_number" name="whatsapp_number" class="input" value="<?= htmlspecialchars($dados['whatsapp_number'] ?? '') ?>" required>
            </div>

            <div class="form-group">
                <label for="whatsapp_message">Mensagem Padrão (Call to Action)</label>
                <span class="hint">Aparecerá abaixo do título no final do site e será o texto enviado pelo visitante ao abrir o WhatsApp.</span>
                <input type="text" id="whatsapp_message" name="whatsapp_message" class="input" value="<?= htmlspecialchars($dados['whatsapp_message'] ?? '') ?>">
            </div>

            <button type="submit" name="salvar_cta" class="btn">Salvar Configurações</button>
        </form>
    </div>

</div>

<script>
    function switchTab(tabId) {
        document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
        
        event.target.classList.add('active');
        document.getElementById('tab-' + tabId).classList.add('active');

        // Atualiza a URL sem recarregar para manter a aba após form submit falho no F5
        window.history.replaceState(null, null, "?tab=" + tabId);
    }
</script>

</body>
</html>
