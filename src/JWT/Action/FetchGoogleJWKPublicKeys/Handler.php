<?php

declare(strict_types=1);

namespace Kreait\Firebase\JWT\Action\FetchGoogleJWKPublicKeys;

use Kreait\Firebase\JWT\Action\FetchGoogleJWKPublicKeys;
use Kreait\Firebase\JWT\Contract\Keys;
use Kreait\Firebase\JWT\Error\FetchingGooglePublicKeysFailed;

interface Handler
{
    /**
     * @throws FetchingGooglePublicKeysFailed
     */
    public function handle(FetchGoogleJWKPublicKeys $action): Keys;
}
