<?php
/** @var \App\View\AppView $this */
/** @var array $states */
/** @var string $notice */
$url = $this->Url->build(['_name' => 'poc02-sessions']);
$labels = ['guest' => 'ゲスト', 'member' => '一般会員', 'admin' => '管理者'];
?>
<!doctype html>
<html lang="ja">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>POC-02 セッション検証</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
          integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
</head>
<body>
<main class="container py-4">
    <h1>POC-02 セッション検証</h1>
    <p><a href="<?= h($url) ?>">全セッションの状態を表示</a></p>
    <?php if ($notice !== '') : ?>
        <p class="alert alert-info" role="status"><?= h($notice) ?></p>
    <?php endif ?>
    <div class="row g-3">
    <?php foreach ($states as $kind => $state) : ?>
        <section class="col-lg-4" data-kind="<?= h($kind) ?>" data-active="<?= empty($state['active']) ? '0' : '1' ?>">
            <div class="card p-3">
            <h2 class="h4"><?= h($labels[$kind]) ?></h2>
            <?php if (!empty($state['active'])) : ?>
                <p>有効 · 最大期限 <?= h(gmdate('Y-m-d H:i:s', $state['expires'])) ?> UTC</p>
                <?php if ($state['subject'] !== null) : ?>
                    <p><?= h($state['subject']) ?></p>
                <?php endif ?>
            <?php else : ?>
                <p>未開始または失効済み</p>
            <?php endif ?>
            <?php if (isset($state['learning'])) : ?>
                <p>回答 <?= h((string)array_sum(array_column($state['learning']['exercises'], 'answers'))) ?> 件
                   · ブックマーク <?= h((string)count($state['learning']['bookmarks'])) ?> 件</p>
                <?php foreach ($state['learning']['exercises'] as $item => $exercise) : ?>
                    <p>演習 <?= h((string)$item) ?> · <?= h((string)$exercise['answers']) ?> 件
                       · <?= $exercise['finished'] ? '終了済み' : '進行中' ?></p>
                <?php endforeach ?>
                <?php if ($state['learning']['bookmarks']) : ?>
                    <p>ブックマーク番号 <?= h(implode(', ', array_keys($state['learning']['bookmarks']))) ?></p>
                <?php endif ?>
            <?php endif ?>
            <?= $this->Form->create(null, ['url' => $url]) ?>
            <?= $this->Form->hidden('kind', ['value' => $kind]) ?>
            <?php if ($kind === 'guest') : ?>
                <?php if (isset($state['learning'])) : ?>
                    <?= $this->Form->hidden('revision', ['value' => $state['revision']]) ?>
                    <label for="poc02-item">演習またはブックマークの番号</label>
                    <input class="form-control mb-2" type="number" id="poc02-item" name="item" min="1" value="1">
                    <button class="btn btn-primary mb-2" name="operation" value="answer">ダミー回答を保存</button>
                    <button class="btn btn-outline-primary mb-2" name="operation" value="finish">演習終了</button>
                    <button class="btn btn-outline-primary mb-2" name="operation" value="bookmark">ブックマーク追加</button>
                    <button class="btn btn-outline-primary mb-2" name="operation" value="unbookmark">ブックマーク解除</button>
                <?php else : ?>
                    <button class="btn btn-primary mb-2" name="operation" value="create">ゲストセッション開始</button>
                <?php endif ?>
            <?php else : ?>
                <label for="subject-<?= h($kind) ?>">検証用アカウント</label>
                <select class="form-select mb-2" id="subject-<?= h($kind) ?>" name="subject">
                    <option value="sample-a">sample-a</option>
                    <option value="sample-b">sample-b</option>
                </select>
                <button class="btn btn-primary mb-2" name="operation" value="login">検証用ログイン</button>
            <?php endif ?>
            <?php if (!empty($state['active'])) : ?>
                <button class="btn btn-outline-secondary mb-2" name="operation" value="logout">ログアウト</button>
                <?php if ($kind !== 'guest') : ?>
                    <button class="btn btn-outline-danger mb-2" name="operation" value="disable">アカウント無効化</button>
                <?php endif ?>
                <?php if ($kind === 'admin') : ?>
                    <button class="btn btn-outline-danger mb-2" name="operation" value="revoke">認証リセット</button>
                <?php endif ?>
            <?php endif ?>
            <?= $this->Form->end() ?>
            </div>
        </section>
    <?php endforeach ?>
    </div>
</main>
</body>
</html>
