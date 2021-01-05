# Attacks on Diffie-Hellman Protocols
## Description
Just labs for education only.\
Lab description you can find [here](https://gist.github.com/arkadiyt/5b33bed653ce1dc26e1df9c249d8919e).
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