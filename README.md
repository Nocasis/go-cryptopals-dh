# Attacks on Diffie-Hellman Protocols
## Description
The labs are for educational purposes.\
Their description can be found [here](https://gist.github.com/arkadiyt/5b33bed653ce1dc26e1df9c249d8919e).
## Tests for DH
### Run all tests
```bash
go test ./pkg/dh
```

### Run test for easy DH attacks
```bash
go test ./pkg/dh - run TestEasyDHAttack
```

### Run test for small subgroup attack
```bash
go test ./pkg/dh -run TestSmallSubGroupAttack
```

### Run test for Pollard's Method for Catching Kangaroos Algorithm
```bash
go test ./pkg/dh -run TestCatchingKangarooAlgorithm
```

[comment]: <> (### Run test for Catching Kangaroos Attack in quick mode)

[comment]: <> (#### In this case we truncate the Bobs private key, a border&#40;right one&#41; of indexes in kangaroo algorithm to uint64Max. )

[comment]: <> (```bash)

[comment]: <> (go test ./pkg/dh -run TestCatchingKangaroosAttackQuick)

[comment]: <> (```)

### Run test for Catching Kangaroos Attack
```bash
go test ./pkg/dh -v -run TestCatchingKangaroosAttack
```

## Tests for ECDH
### Run tests for elliptic operations
#### Copied patterns and tests from [this](https://github.com/dnkolegov/dhpals/tree/master/elliptic) repository
#### Pseudocode for basic EC operation can be found [here](https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication).
```bash
go test ./pkg/elliptic
```

### Invalid-Curve Attack
```bash
go test ./pkg/elliptic -run TestECDHInvalidCurveAttack
```

### Test cswap operation of The Montgomery curve
```bash
go test ./pkg/x128 -run TestCswap
```

### Test the Montgomery ladder
```bash
go test ./pkg/x128 -run TestBasicLadder
```
```bash
go test ./pkg/elliptic -v -run TestCurvesP128AndX128 
```
### Insecure Twists Attack

```bash
go test ./pkg/elliptic -timeout 3h -v -run TestTwistAttack
```
