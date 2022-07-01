<?php

declare(strict_types=1);

namespace Kreait\Firebase\JWT\Action\VerifyIdToken;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;

final class IssuedByStartWith implements Constraint
{
    /** @var string[] */
    private array $issuers;

    public function __construct(string ...$issuers)
    {
        $this->issuers = $issuers;
    }

    public function asIssued(Token $token, string ...$issuers): bool
    {
        $tokenIssuer = $token->claims->get(RegisteredClaims::ISSUER);
        foreach ($issuers as $issuer) {
            if (str_starts_with($tokenIssuer, $issuer)) {
                return true;
            }
        }

        return false;
    }

    public function assert(Token $token): void
    {
        if (! $this->asIssued($token, ...$this->issuers)) {
            throw new ConstraintViolation(
                'The token was not issued by the given issuers'
            );
        }
    }
}
