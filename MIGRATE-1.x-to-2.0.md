# Migrating from 1.x to 2.x

This guide will help you to miograte from a 1.x to a 2.x version. If you are updating from a <1.9 version, consider
updating to 1.9 first so that you can benefit from deprecation notices in your IDE.

## Changed return values

## Tokens

In 1.x, the Custom Token Generator and ID Token verifier returned instances of `Lcobucci\JWT\Token`.

In 2.0, the Custom Token Generator and ID Token verifier return instances of `Kreait\Firebase\JWT\Contracts\Token`.

## Error Handling

In 1.x, specialized exceptions types were thrown for different kind of errors.

In 2.x, only one exception per action is thrown.

- `Kreait\Firebase\JWT\Error\CustomTokenCreationFailed`
- `Kreait\Firebase\JWT\Error\IdTokenVerificationFailed`

## Changed usage

### Custom Token Generator

Replace usages of `Firebase\Auth\Token\Generator` with `Kreait\Firebase\JWT\CustomTokenGenerator`:

#### 1.x usage

```php
<?php

// Before
use Firebase\Auth\Token\Generator;

$generator = new Generator($clientEmail, $privateKey);
$token = $generator->createCustomToken($uid, $claims);
// Returns an instance of Lcobucci\JWT\Token
``` 

#### 2.0 usage

```php
<?php

use Kreait\Firebase\JWT\CustomTokenGenerator;

$generator = CustomTokenGenerator::withClientEmailAndPrivateKey($clientEmail, $privateKey);
$token = $generator->createCustomToken($uid, $claims);
// Returns an instance of Kreait\Firebase\JWT\Contracts\Token
```

### ID Token Verifier

Replace usages of `Firebase\Auth\Token\Verifier` with `Kreait\Firebase\JWT\IdTokenVerifier`:

#### 1.x usage

```php
<?php

use Firebase\Auth\Token\Verifier;

$verifier = new Verifier($projectId);

try {
    $verifiedIdToken = $verifier->verifyIdToken($idToken);
    
    echo $verifiedIdToken->getClaim('sub'); // "a-uid"
} catch (\Firebase\Auth\Token\Exception\ExpiredToken $e) {
    echo $e->getMessage();
} catch (\Firebase\Auth\Token\Exception\IssuedInTheFuture $e) {
    echo $e->getMessage();
} catch (\Firebase\Auth\Token\Exception\InvalidToken $e) {
    echo $e->getMessage();
}
```

#### 2.0 usage

```php
<?php

use Kreait\Firebase\JWT\Error\IdTokenVerificationFailed;
use Kreait\Firebase\JWT\IdTokenVerifier;

$verifier = IdTokenVerifier::createWithProjectId($projectId);

try {
    $verifier->verifyIdToken('header.payload.signature');
} catch (IdTokenVerificationFailed $e) {
    echo $e->getMessage();
    // Example Output:
    // The value 'idTokenString' is not a verified ID token:
    // - The token is invalid.
    // - Wrong number of segments
}
```

