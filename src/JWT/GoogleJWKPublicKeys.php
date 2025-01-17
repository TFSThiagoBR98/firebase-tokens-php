<?php

declare(strict_types=1);

namespace Kreait\Firebase\JWT;

use Beste\Clock\SystemClock;
use GuzzleHttp\Client;
use Kreait\Firebase\JWT\Action\FetchGoogleJWKPublicKeys;
use Kreait\Firebase\JWT\Action\FetchGoogleJWKPublicKeys\Handler;
use Kreait\Firebase\JWT\Action\FetchGoogleJWKPublicKeys\WithGuzzle;
use Kreait\Firebase\JWT\Contract\Expirable;
use Kreait\Firebase\JWT\Contract\Keys;
use StellaMaris\Clock\ClockInterface;

final class GoogleJWKPublicKeys implements Keys
{
    private ClockInterface $clock;

    private Handler $handler;

    private ?Keys $keys = null;

    public function __construct(?Handler $handler = null, ?ClockInterface $clock = null)
    {
        $this->clock = $clock ?: SystemClock::create();
        $this->handler = $handler ?: new WithGuzzle(new Client(['http_errors' => false]), $this->clock);
    }

    public function all(): array
    {
        $keysAreThereButExpired = $this->keys instanceof Expirable && $this->keys->isExpiredAt($this->clock->now());

        if (!$this->keys || $keysAreThereButExpired) {
            $this->keys = $this->handler->handle(FetchGoogleJWKPublicKeys::fromGoogle());
            // There is a small chance that we get keys that are already expired, but at this point we're happy
            // that we got keys at all. The next time this method gets called, we will re-fetch.
        }

        return $this->keys->all();
    }
}
