# qproxy

TCP-over-QUIC прокси

Сборка:
```
git clone --recursive https://github.com/markh04/qproxy
cd qproxy
go build client/qclient.go
go build server/qserver.go
```

Запуск:
```
# Сервер
./qserver [--listen <addr:port local>] <addr:port target> [/path/to/tls/pubkey /path/to/tls/privkey]

# Клиент
./qclient [--listen <addr:port local>] <addr:port server>
```

Без указания сертификата сгенерируется случайный.

```
.-----------.            .-----------.
|  client   |            |  server   |
'-----------'            '-----------'
    |  ^                     ^  |
    v  |                     |  v
.-----------.            .-----------.
|  qclient  | <--------> |  qserver  |
'-----------'            '-----------'
```

Опционально: Docker (запуск клиента)
```
1. Указать ключи в docker-compose.yml
2. docker compose build
3. # Запуск
   docker compose up
```
