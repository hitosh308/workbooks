<?php
declare(strict_types=1);

namespace App\Controller\Poc02;

use App\Controller\AppController;
use App\Middleware\Poc02AccessMiddleware;
use App\Poc02\SessionKind;
use App\Poc02\Sessions;
use App\Poc02\SessionStore;
use Cake\Http\Response;
use Exception;

final class SessionsController extends AppController
{
    /**
     * Render the session status page or process one CSRF-protected operation.
     */
    public function index(): Response
    {
        $request = $this->getRequest();
        $response = $this->getResponse()
            ->withHeader('Cache-Control', 'no-store, private')
            ->withHeader('Referrer-Policy', 'no-referrer');
        if (!Poc02AccessMiddleware::allows($request)) {
            return $response->withStatus(404);
        }

        $request->allowMethod(['get', 'post']);
        $states = [];
        $notice = '';
        $status = 200;
        if ($request->is('post')) {
            $value = $request->getData('kind');
            $kind = is_string($value) ? SessionKind::tryFrom($value) : null;
            $operation = $request->getData('operation');
            $allowed = match ($kind) {
                SessionKind::Guest => ['create', 'logout', 'answer', 'finish', 'bookmark', 'unbookmark'],
                SessionKind::Member => ['login', 'logout', 'disable'],
                SessionKind::Admin => ['login', 'logout', 'disable', 'revoke'],
                null => [],
            };
            if (!in_array($operation, $allowed, true)) {
                return $response->withStatus(422);
            }
            $kinds = [$kind];
        } else {
            $operation = 'status';
            $kinds = SessionKind::cases();
        }

        try {
            foreach ($kinds as $kind) {
                $sessions = new Sessions(SessionStore::forKind($kind), $kind);
                $state = $sessions->handle(
                    $request->getCookie($kind->cookie()),
                    $operation,
                    (array)$request->getData(),
                );
                if ($state['cookie'] ?? null) {
                    $response = $response->withCookie($state['cookie']);
                }
                unset($state['cookie']);
                $status = $state['status'];
                $notice = $state['notice'] ?: $notice;
                $states[$kind->value] = $state;
            }
        } catch (Exception) {
            $status = 503;
            $notice = 'セッションの読み書きに失敗しました。画面を開き直してから再試行してください。';
            $states = [];
        }

        $this->viewBuilder()->disableAutoLayout();
        $this->set(compact('states', 'notice'));
        $this->setResponse($response->withStatus($status));

        return $this->render();
    }
}
