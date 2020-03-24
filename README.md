# tss-lib-test

## Build with test data
```
git clone https://github.com/seemenkina/tss-lib-test.git
cd tss-lib-test/
go run main.go
```

## Build with new test data
```
git clone https://github.com/seemenkina/tss-lib-test.git
cd tss-lib-test/
rm /test_data/cert/*
rm /test_data/ecdsa_data/*
go run main.go
```