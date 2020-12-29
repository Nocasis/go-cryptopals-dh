# Attacks on Diffie-Hellman Protocols
## Description
Just labs for education only.\
Lab description you can find [here](https://gist.github.com/arkadiyt/5b33bed653ce1dc26e1df9c249d8919e).
## Tests
### Run all tests
```bash
go test ./pkg/dh
```

### Run test for small subgroup attack
```bash
go test ./pkg/dh -run TestSmallSubGroupAttack
```
