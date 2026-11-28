<?php
declare(strict_types=1);

namespace App\Poc02;

use Cake\Http\Session;

final class GuestLearning
{
    private const VERSION = 1;

    /**
     * Check the learning schema and apply an update at the current revision.
     */
    public static function update(Session $session, array &$record, string $operation, array $input): array
    {
        $data = $session->read('Learning');
        $reset = $data !== null && ($data['schema_version'] ?? null) !== self::VERSION;
        if ($data === null || $reset) {
            $data = ['schema_version' => self::VERSION, 'exercises' => [], 'bookmarks' => []];
        }
        if ($reset) {
            $record['revision']++;
        }

        $status = 200;
        $notice = $record['notice'] || $reset ? '非互換のゲスト学習データを初期化しました。' : '';
        if (in_array($operation, ['answer', 'finish', 'bookmark', 'unbookmark'], true)) {
            $revision = $input['revision'] ?? null;
            if ((!is_string($revision) && !is_int($revision)) || (string)$revision !== (string)$record['revision']) {
                $status = 409;
                $notice .= ' 最新の画面を開き直してから再試行してください。';
            } else {
                [$status, $message] = self::change($data, $operation, $input);
                $notice .= $message;
                if ($status === 200) {
                    $record['revision']++;
                }
            }
        }
        // A reset discovered during a POST is also announced on the next status page.
        $record['notice'] = $operation !== 'status' && ($record['notice'] || $reset);
        $session->write('Learning', $data);

        return [
            'status' => $status,
            'notice' => trim($notice),
            'learning' => $data,
            'revision' => $record['revision'],
        ];
    }

    /**
     * Apply one demonstration learning operation.
     */
    private static function change(array &$data, string $operation, array $input): array
    {
        $item = filter_var($input['item'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
        if ($item === false) {
            return [422, '正の整数を入力してください。'];
        }
        if ($operation === 'bookmark') {
            if (!isset($data['bookmarks'][$item]) && count($data['bookmarks']) >= 100) {
                return [409, '先に既存のブックマークを解除してください。'];
            }
            $data['bookmarks'][$item] = true;

            return [200, 'ブックマークを保存しました。'];
        }
        if ($operation === 'unbookmark') {
            unset($data['bookmarks'][$item]);

            return [200, 'ブックマークを解除しました。'];
        }

        $exercises = $data['exercises'];
        if ($operation === 'finish') {
            if (!isset($exercises[$item])) {
                return [422, '演習が見つかりません。'];
            }
            $data['exercises'][$item]['finished'] = $data['exercises'][$item]['finished']
                ?: self::nextFinishedOrder($exercises);

            return [200, '演習を終了しました。'];
        }

        if (!empty($exercises[$item]['finished'])) {
            return [409, 'この演習は終了済みです。'];
        }
        $exercises[$item] ??= ['finished' => 0, 'answers' => 0];
        $exercises[$item]['answers']++;
        if (array_sum(array_column($exercises, 'answers')) > 500) {
            $finished = array_filter(array_map(static fn(array $exercise): int => $exercise['finished'], $exercises));
            if ($finished === []) {
                return [409, '回答上限です。進行中の演習を保護するため保存できません。'];
            }
            asort($finished, SORT_NUMERIC);
            unset($exercises[array_key_first($finished)]);
        }
        $data['exercises'] = $exercises;

        return [200, '回答を保存しました。'];
    }

    /**
     * Assign a completion order independent of wall clock resolution.
     */
    private static function nextFinishedOrder(array $exercises): int
    {
        return max(array_column($exercises, 'finished')) + 1;
    }
}
