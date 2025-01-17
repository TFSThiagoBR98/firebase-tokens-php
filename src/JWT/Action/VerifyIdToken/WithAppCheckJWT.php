<?php

declare(strict_types=1);

namespace Kreait\Firebase\JWT\Action\VerifyIdToken;

use DateInterval;
use DateTimeImmutable;
use DateTimeInterface;
use Kreait\Firebase\JWT\Action\VerifyIdToken;
use Kreait\Firebase\JWT\Contract\Keys;
use Kreait\Firebase\JWT\Contract\Token;
use Kreait\Firebase\JWT\Action\VerifyIdToken\IssuedByStartWith;
use Kreait\Firebase\JWT\Error\IdTokenVerificationFailed;
use Kreait\Firebase\JWT\Token as TokenInstance;
use Kreait\Firebase\JWT\Util;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\None;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\JWT\Validation\Validator;
use StellaMaris\Clock\ClockInterface;
use Throwable;

/**
 * @internal
 */
final class WithAppCheckJWT implements Handler
{
    private string $projectId;
    private Keys $keys;
    private ClockInterface $clock;
    private Parser $parser;
    private Signer $signer;
    private Validator $validator;

    public function __construct(string $projectId, Keys $keys, ClockInterface $clock)
    {
        $this->projectId = $projectId;
        $this->keys = $keys;
        $this->clock = $clock;
        $this->parser = new Parser(new JoseEncoder());

        if (Util::authEmulatorHost() !== '') {
            $this->signer = new None();
        } else {
            $this->signer = new Sha256();
        }

        $this->validator = new Validator();
    }

    public function handle(VerifyIdToken $action): Token
    {
        $tokenString = $action->token();

        try {
            $token = $this->parser->parse($tokenString);
            \assert($token instanceof UnencryptedToken);
        } catch (Throwable $e) {
            throw IdTokenVerificationFailed::withTokenAndReasons($tokenString, ['The token is invalid', $e->getMessage()]);
        }

        $key = $this->getKey($token);
        $clock = new FrozenClock($this->clock->now());
        $leeway = new DateInterval('PT'.$action->leewayInSeconds().'S');
        $errors = [];

        $constraints = [
            new LooseValidAt($clock, $leeway),
            new IssuedByStartWith(...["https://firebaseappcheck.googleapis.com/"]),
            new PermittedFor("projects/" . $this->projectId),
        ];

        if ($key !== '' && Util::authEmulatorHost() === '') {
            $constraints[] = new SignedWith($this->signer, InMemory::plainText($key));
        }

        try {
            $this->validator->assert($token, ...$constraints);
        } catch (RequiredConstraintsViolated $e) {
            $errors = \array_map(
                static fn (ConstraintViolation $violation): string => '- '.$violation->getMessage(),
                $e->violations()
            );
        }

        if (!empty($errors)) {
            throw IdTokenVerificationFailed::withTokenAndReasons($tokenString, $errors);
        }

        $claims = $token->claims()->all();

        foreach ($claims as &$claim) {
            if ($claim instanceof DateTimeInterface) {
                $claim = $claim->getTimestamp();
            }
        }
        unset($claim);

        $headers = $token->headers()->all();
        foreach ($headers as &$header) {
            if ($header instanceof DateTimeInterface) {
                $header = $header->getTimestamp();
            }
        }
        unset($header);

        return TokenInstance::withValues($tokenString, $headers, $claims);
    }

    private function getKey(UnencryptedToken $token): string
    {
        if (empty($keys = $this->keys->all())) {
            throw IdTokenVerificationFailed::withTokenAndReasons($token->toString(), ["No keys are available to verify the token's signature."]);
        }

        $keyId = $token->headers()->get('kid');

        if ($key = $keys[$keyId] ?? null) {
            return $key;
        }

        if ($this->signer instanceof None) {
            return '';
        }

        throw IdTokenVerificationFailed::withTokenAndReasons($token->toString(), ["No public key matching the key ID '{$keyId}' was found to verify the signature of this token."]);
    }
}
