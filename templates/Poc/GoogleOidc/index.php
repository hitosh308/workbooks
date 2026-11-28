<?php
/**
 * @var \App\View\AppView $this
 * @var bool $configured
 * @var bool $signedIn
 * @var string|null $result
 */
$messages = [
    'authenticated' => 'Google ログイン成功',
    'reauthenticated' => '同一アカウントでの本人再認証を確認しました。',
    'unconfigured' => '検証用 Google OAuth 設定が必要です。',
    'login-required' => '本人再認証を始めるには Google ログインが必要です。',
    'invalid' => '認証要求が無効か期限切れです。最初からやり直してください。',
    'cancelled' => 'Google 認証がキャンセルされました。',
    'google-error' => 'Google から認証エラーが返されました。',
    'verification-failed' => 'Google との通信または認証結果の検証に失敗しました。',
    'different-account' => 'ログイン時と異なる Google アカウントです。',
    'stale' => 'Google の本人認証が再認証開始より後であることを確認できませんでした。',
    'freshness-unavailable' => 'Google の本人認証時刻を確認できませんでした。',
];
?>
<!doctype html>
<html lang="ja">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css"
        integrity="sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqkuIAvNWLzeN8tE5YBujZqJLB"
        crossorigin="anonymous">
    <title>Google OIDC 技術検証</title>
</head>
<body>
<main class="container py-4">
    <h1>Google OIDC 技術検証</h1>
    <?php if ($result !== null && isset($messages[$result])) : ?>
        <p role="status"><?= h($messages[$result]) ?></p>
    <?php endif; ?>
    <?php if ($configured) : ?>
        <?= $this->Form->create(null, ['url' => ['_name' => 'poc-google-oidc-start']]) ?>
        <button class="btn btn-primary" name="mode" value="login" type="submit">Google ログイン</button>
        <?php if ($signedIn) : ?>
            <button class="btn btn-secondary" name="mode" value="reauth" type="submit">本人再認証</button>
        <?php endif; ?>
        <?= $this->Form->end() ?>
    <?php else : ?>
        <p>検証用 Google OAuth 設定が必要です。</p>
    <?php endif; ?>
</main>
</body>
</html>
