<?php
declare(strict_types=1);

namespace App\Controller\Poc;

use App\Controller\AppController;
use App\Poc\GoogleOidc;
use Cake\Http\Exception\NotFoundException;
use Cake\Http\Response;
use Throwable;

final class GoogleOidcController extends AppController
{
    private const SESSION = 'Poc.GoogleOidc.';

    /** @inheritDoc */
    public function initialize(): void
    {
        parent::initialize();
        if (!GoogleOidc::enabled()) {
            throw new NotFoundException();
        }

        $this->viewBuilder()->disableAutoLayout();
        $this->setResponse($this->getResponse()
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Referrer-Policy', 'no-referrer'));
    }

    /**
     * @param \App\Poc\GoogleOidc $google The PoC client.
     * @return void
     */
    public function index(GoogleOidc $google): void
    {
        $this->request->allowMethod(['get']);
        $session = $this->request->getSession();
        $this->set([
            'configured' => $google->configured(),
            'signedIn' => $session->check(self::SESSION . 'subject'),
            'result' => $session->consume(self::SESSION . 'result'),
        ]);
    }

    /**
     * @param \App\Poc\GoogleOidc $google The PoC client.
     * @return \Cake\Http\Response
     */
    public function start(GoogleOidc $google): Response
    {
        $this->request->allowMethod(['post']);
        $session = $this->request->getSession();
        $session->delete(self::SESSION . 'transaction');
        $session->delete(self::SESSION . 'result');
        if (!$google->configured()) {
            return $this->finish('unconfigured');
        }

        $mode = $this->request->getData('mode');
        $subject = null;
        if ($mode === 'reauth') {
            $subject = $session->read(self::SESSION . 'subject');
            if (!is_string($subject)) {
                return $this->finish('login-required');
            }
        } elseif ($mode !== 'login') {
            return $this->finish('invalid');
        }

        $transaction = $google->transaction($subject);
        $session->write(self::SESSION . 'transaction', $transaction);

        return $this->redirect($google->authorizationUrl($transaction), 303);
    }

    /**
     * @param \App\Poc\GoogleOidc $google The PoC client.
     * @return \Cake\Http\Response
     */
    public function callback(GoogleOidc $google): Response
    {
        $this->request->allowMethod(['get']);
        $session = $this->request->getSession();
        $transaction = $session->consume(self::SESSION . 'transaction');
        $state = $this->request->getQuery('state');
        if (
            !$google->configured() || !is_array($transaction) || !is_string($state)
            || !hash_equals($transaction['state'], $state)
            || time() - $transaction['startedAt'] > GoogleOidc::LIFETIME
        ) {
            return $this->finish('invalid');
        }

        $issuer = $this->request->getQuery('iss');
        if ($issuer !== null && $issuer !== GoogleOidc::ISSUER) {
            return $this->finish('invalid');
        }

        $error = $this->request->getQuery('error');
        if ($error !== null) {
            return $this->finish($error === 'access_denied' ? 'cancelled' : 'google-error');
        }

        $code = $this->request->getQuery('code');
        if (!is_string($code) || $code === '') {
            return $this->finish('invalid');
        }

        try {
            $result = $google->verify($code, $transaction);
        } catch (Throwable) {
            return $this->finish('verification-failed');
        }

        if (isset($result['error'])) {
            return $this->finish($result['error']);
        }

        if ($transaction['subject'] !== null) {
            if ($session->read(self::SESSION . 'subject') !== $transaction['subject']) {
                return $this->finish('different-account');
            }

            return $this->finish('reauthenticated');
        }

        $session->renew();
        $session->write(self::SESSION . 'subject', $result['subject']);

        return $this->finish('authenticated');
    }

    /**
     * @param string $result Message key for the result page.
     * @return \Cake\Http\Response
     */
    private function finish(string $result): Response
    {
        $this->request->getSession()->write(self::SESSION . 'result', $result);

        return $this->redirect(['_name' => 'poc-google-oidc'], 303);
    }
}
