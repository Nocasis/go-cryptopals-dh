# go-cryptopals-dh
## Как запускать тесты
Запустить тесты можно так:
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

### Run test for Catching Kangaroos Attack in quick mode
#### In this case we truncate the Bobs private key, a border(right one) of indexes in kangaroo algorithm to uint64Max. 
```bash
go test ./pkg/dh -run TestCatchingKangaroosAttackQuick
```

### Run test for Catching Kangaroos Attack in slow mode
#### Real case. It can work for a really long time.
```bash
go test ./pkg/dh -timeout 1440m -v -run TestCatchingKangaroosAttackLong
```
## Tests for ECDH
### Run tests for elleptic operations. All EC basic operations can be found [here](https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication).
#### Copied from [this](https://github.com/dnkolegov/dhpals/tree/master/elliptic) repository
```bash
go test ./pkg/elliptic
```