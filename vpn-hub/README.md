# vpn-hub

Тонкий self-hosted middleware между коммерческими VPN-подписками и клиентом
mihomo (Clash.Meta / FlClash / Clash Verge и т.п.).

## Зачем это

Коммерческие подписки часто отдают ноды в формате xray-JSON (массив профилей
с `remarks` + `outbounds`) по одноразовому подписочному URL, который провайдер
периодически пересоздаёт. mihomo-клиенту же удобнее `proxy-provider` с
YAML-нодами и **стабильными именами**, чтобы собирать группы фильтром по regex.

vpn-hub решает это:

- **live-pull на каждый запрос**: клиент всегда качает с фиксированного
  `https://sub.example.com:8443/<source>.yaml`, а хаб на лету тянет актуальный
  upstream. Провайдер пересоздал ссылку? Меняешь её один раз в конфиге хаба,
  клиент не трогаешь.
- **xray-JSON → mihomo** конверсия inline (vless + reality/tls, tcp/xhttp).
- **стабильные имена** нод: `<source>-{main|antiblock|backup}-NN`, по ним
  клиент собирает группы через `use:` + `filter:`.
- **failover-кэш** на диске: если upstream недоступен в момент запроса,
  отдаётся последний удачный ответ.
- **несколько подписок за одним доменом**, каждая на своём пути.

## Ограничения (прочитай перед развёртыванием)

- Работает **только с подписками, отдающими xray-JSON** (формат, который качают
  клиенты вроде V2Box / Happ / Hiddify-панелей). Если твоя подписка отдаёт
  base64-список `vless://...` или готовый Clash-YAML, этот конвертер без правок
  не подойдёт.
- Конвертит только `vless` (reality или tls, network `tcp`/`raw`/`xhttp`,
  старое имя `splithttp` тоже принимается). vmess/trojan/ss/hysteria и прочие
  network пропускаются. Допилить под свой протокол можно в `convert_outbound()`.
- Битая нода (нет `publicKey`, кривой port/uuid, неподдерживаемый network)
  пропускается. Остальные профили этой подписки всё равно отдаются.
- Ключ source — это путь `/<key>.yaml` и префикс имён. Только латиница, цифры,
  `_` и `-`. Если `dialect` не задан, ключ с именем диалекта (`govpn`,
  `buzzvpn`, `generic`) выбирает этот диалект.
- Ссылка вида `https://host/happ?token=...` — HTML-страница установки Happ, не
  тело подписки. В `url` хаба нужна JSON-выдача; у такой панели это
  `https://host/api/sub?token=...`. Без заголовка `x-hwid` она отвечает
  `SUBSCRIPTION_HWID_REQUIRED` (один постоянный `x-hwid` = один слот устройства).
- Такие подписки часто присылают несколько полных xray-конфигов с одними и теми
  же vless-нодами. Хаб оставляет первую копию каждой ноды: «Автоматический» и
  «Обход LTE» отличаются маршрутизацией клиента, а не серверами.

## Файлы

| Файл | Что |
|---|---|
| `render.py` | Сам движок: stdlib HTTP-сервер, конверсия, кэш. Кладётся в `/opt/vpn-hub/`. `--config PATH` переопределяет конфиг (по умолчанию `/etc/vpn-hub/config.yaml`). |
| `config.example.yaml` | Шаблон конфига → `/etc/vpn-hub/config.yaml`. Свои URL подписок, UA, headers. |
| `systemd/vpn-hub.service` | systemd-юнит (запуск от отдельного юзера, sandbox-хардненинг). |
| `Caddyfile.example` | Reverse-proxy Caddy: TLS + basic_auth + авто-ACME. |
| `requirements.txt` | Единственная зависимость: PyYAML. |
| `tests/` | Юнит-тесты конвертера и HTTP-слоя. |

## Что нужно

- Сервер с публичным IP и доменом (A-запись `sub.example.com` → IP).
- Python 3.10+ и PyYAML (`apt install python3-yaml` или `pip install -r requirements.txt`).
- Caddy v2 (auto-TLS через Let's Encrypt).
- Хотя бы одна подписка в формате xray-JSON.

## Установка

```sh
# 1. Отдельный служебный юзер + файлы движка
sudo useradd --system --no-create-home --shell /usr/sbin/nologin vpn-hub
sudo install -D -m 0755 render.py /opt/vpn-hub/render.py

# 2. Конфиг (правь под себя: url / user_agent / headers / dialect)
sudo install -D -m 0640 config.example.yaml /etc/vpn-hub/config.yaml
sudo chown root:vpn-hub /etc/vpn-hub/config.yaml
sudo nano /etc/vpn-hub/config.yaml

# 3. systemd
sudo install -D -m 0644 systemd/vpn-hub.service /etc/systemd/system/vpn-hub.service
sudo systemctl daemon-reload
sudo systemctl enable --now vpn-hub.service
curl -s http://127.0.0.1:8080/healthz      # ok=True + строка на каждый source

# 4. Caddy: домен, логин, пароль-хеш, список endpoint'ов
caddy hash-password                        # введи пароль, скопируй bcrypt-хеш
sudo cp Caddyfile.example /etc/caddy/Caddyfile
sudo nano /etc/caddy/Caddyfile             # sub.example.com, __USERNAME__, __PASSWORD_HASH__, @hub path
sudo mkdir -p /var/log/caddy
sudo systemctl reload caddy

# 5. Firewall
sudo ufw allow 80/tcp        # ACME
sudo ufw allow 8443/tcp      # hub
```

При старте хаб один раз тянет каждый source и только потом начинает отвечать.
`healthz` в этот момент показывает, жива ли подписка (или есть ли кэш с прошлого
раза). Дальше каждый `GET /<source>.yaml` снова ходит в upstream.

Smoke с клиента:

```sh
curl -u LOGIN:PASSWORD https://sub.example.com:8443/healthz
curl -u LOGIN:PASSWORD -D- -o- https://sub.example.com:8443/myvpn.yaml | head -30
```

## Диалекты (адаптация под свою подписку)

Хаб раскладывает ноды по трём корзинам `main` / `antiblock` / `backup` по тексту
`remarks` каждого профиля. Правило задаёт **диалект** в `DIALECTS` (в `render.py`):

- `generic` (дефолт) — всё уходит в `main`. Подходит, если тебе не нужно делить
  ноды по режимам. Просто `dialect: generic` в конфиге source.
- `govpn` / `buzzvpn` — примеры реальных провайдеров: `detect`-функция смотрит на
  русские метки в `remarks` («Антизаглушка», «Обход белых списков» и т.п.) и
  раскидывает ноды по корзинам.

Свой диалект = добавить функцию `detect_mode_*(remarks) -> "main"|"antiblock"|"backup"|"unknown"`
и запись в `DIALECTS`, затем `dialect: <имя>` в конфиге source. `unknown` = ноду
пропустить (так, например, отбрасываются агрегаты-балансировщики).

`fingerprint`: `random` жёстко ставит uTLS-fingerprint, `upstream` берёт тот,
что прислала подписка (fallback на random).

Поля xhttp из `xhttpSettings.extra` (padding, xmux, downloadSettings) кладутся
в `xhttp-opts` так же, как это делает конвертер mihomo. Старый плоский вид
(`xPaddingBytes` и `reuseSettings` рядом с `path`) тоже принимается.

## Клиентская сторона (mihomo)

Ноды подключаются в локальный mihomo-профиль как proxy-provider, группы
собираются фильтром по стабильным именам:

```yaml
proxy-providers:
  myvpn:
    type: http
    url: "https://sub.example.com:8443/myvpn.yaml"
    # basic_auth клиенты mihomo обычно кладут прямо в URL:
    # url: "https://LOGIN:PASSWORD@sub.example.com:8443/myvpn.yaml"
    interval: 3600
    health-check: { enable: true, url: "https://www.gstatic.com/generate_204", interval: 300 }

proxy-groups:
  - name: MyVPN-Main
    type: url-test
    use: [myvpn]
    filter: "myvpn-main-"
  # - name: MyVPN-Antizaglushka
  #   type: url-test
  #   use: [myvpn]
  #   filter: "myvpn-antiblock-"
```

## Безопасность

- basic_auth **обязателен** (иначе твоя подписка открыта всему интернету).
- `render.py` слушает только `127.0.0.1` — наружу выходит исключительно через
  Caddy с TLS.
- Не публикуй подписочный URL и домен хаба. `x-hwid` (если панель его требует)
  держи постоянным: тогда хаб занимает ровно один device-slot подписки.
- Заголовок `subscription-userinfo` от upstream режется до одной ASCII-строки,
  прежде чем уйти клиенту.

## Проверка конвертера

```sh
pip install -r requirements.txt
python -m unittest discover -s tests
```
