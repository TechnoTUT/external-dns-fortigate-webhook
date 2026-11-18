# external-dns-fortigate-webhook

[ExternalDNS](https://github.com/kubernetes-sigs/external-dns) の webhook provider です。Kubernetes の Service や Ingress、DNSEndpoint のレコードを、FortiGate の DNS データベース (`config system dns-database`) に REST API で書き込みます。

TechnoTUT のクラスタ ([TechnoTUT/Infra](https://github.com/TechnoTUT/Infra)) で、`svc.technotut.net` のレコードを FortiGate から直接返すために使います。

## 仕組み

- ExternalDNS の Pod のサイドカーとして動きます。ExternalDNS は `127.0.0.1:8888` の webhook API (version=1) を呼びます。
- 扱うレコードの種類は、正引きのゾーンでは A、AAAA、CNAME です。逆引きのゾーンでは PTR と PTR_V6 です。
- 変更を受け取ると、FortiGate からゾーンを読みます。そこに変更を当て、ゾーンの `dns-entry` 全体を PUT で置き換えます。内容が変わらないときは書き込みません。FortiGate の設定の保存とリビジョンが増えるのは、レコードが実際に変わったときだけです。
- 逆引きのゾーンを指定すると、正引きの A と AAAA から PTR を作ります。ExternalDNS の `--create-ptr` は使いません。逆引きは変更のたびに作り直し、`REVERSE_RESYNC_INTERVAL` ごとにも作り直します。
- 依存は Go の標準ライブラリだけです。

### ゾーンは webhook 専用にする

FortiGate の `dns-entry` には TXT が置けません。そのため ExternalDNS の TXT registry (レコードの所有者の記録) が使えません。この webhook は次のように扱います。

- 正引きのゾーンの A、AAAA、CNAME と、逆引きのゾーンの PTR は、すべて webhook のものとして扱います。
- ExternalDNS は `--registry=noop` で動かします。`policy: sync` なので、Kubernetes 側にないレコードは消えます。
- 手で書きたい固定のレコードは、FortiGate に直接書かないでください。Kubernetes の `DNSEndpoint` として書きます。
- 次のエントリには触りません。ゾーンの頂点 (`@`)、NS や MX などの他の種類、`status disable` のエントリです。

## 設定 (環境変数)

| 変数 | 既定 | 内容 |
|---|---|---|
| `FORTIGATE_URL` | (必須) | 例: `https://192.168.99.129` |
| `FORTIGATE_TOKEN` | | REST API 管理者の API キー |
| `FORTIGATE_TOKEN_FILE` | | API キーをファイルから読む。`FORTIGATE_TOKEN` より優先します |
| `FORTIGATE_TOKEN_IN_QUERY` | `false` | `true` なら、`Authorization: Bearer` ヘッダの代わりにクエリ `access_token` でキーを渡します。ヘッダを受け付けない古い FortiOS 向けです |
| `FORTIGATE_VDOM` | `root` | |
| `FORTIGATE_ZONE` | (必須) | 正引きのゾーンの `dns-database` の名前。ドメインはゾーンの `domain` から読みます |
| `FORTIGATE_REVERSE_ZONES` | | 逆引きのゾーンの `dns-database` の名前 (カンマ区切り)。ゾーンの `domain` は `12.10.in-addr.arpa` のような、オクテット (IPv6 はニブル) で区切った形にします |
| `FORTIGATE_CA_FILE` | | FortiGate の証明書を検証する CA (PEM) |
| `FORTIGATE_INSECURE_SKIP_VERIFY` | `false` | 証明書を検証しません (自己署名の証明書のとき) |
| `DRY_RUN` | `false` | FortiGate に書かず、書く内容をログに出します |
| `REVERSE_RESYNC_INTERVAL` | `5m` | 逆引きのゾーンを作り直す間隔 |
| `WEBHOOK_ADDR` | `127.0.0.1:8888` | webhook API |
| `HEALTH_ADDR` | `:8080` | `/healthz`、`/readyz` |
| `LOG_LEVEL` | `info` | `debug`、`info`、`warn`、`error` |

`/readyz` は、起動してから FortiGate のゾーンを読めるまで 503 を返します。

## FortiGate の設定

1. REST API 管理者のプロファイルを作ります。`dns-database` はシステムの設定 (`sysgrp`) に含まれます。

   ```
   config system accprofile
       edit "externaldns"
           set sysgrp custom
           config sysgrp-permission
               set cfg read-write
           end
       next
   end
   ```

2. REST API 管理者を作って、API キーを発行します。接続元は Pod の通信を NAT したあとの IP (ノードの IP) に絞ります。

   ```
   config system api-user
       edit "externaldns"
           set accprofile "externaldns"
           set vdom "root"
           config trusthost
               edit 1
                   set ipv4-trusthost 192.168.99.128 255.255.255.128
               next
           end
       next
   end
   execute api-user generate-key externaldns
   ```

3. Pod から届くインターフェースで HTTPS の管理アクセスを許可します (例: `dmz` の `allowaccess` に `https` を足す)。

4. ゾーンを用意します。逆引きを使う場合は逆引きのゾーンも作ります。

   ```
   config system dns-database
       edit "svc.technotut.net"
           set domain "svc.technotut.net"
           set authoritative enable
           set ttl 300
           set primary-name "ns1"
           set contact "network.technotut.net"
       next
       edit "12.10.in-addr.arpa"
           set domain "12.10.in-addr.arpa"
           set authoritative enable
           set ttl 300
           set primary-name "ns1"
           set contact "network.technotut.net"
       next
   end
   ```

5. クライアントや CoreDNS が問い合わせるインターフェースの `config system dns-server` を `recursive` か `non-recursive` にします。`forward-only` だと、ローカルの DNS データベースを参照しません。

## ExternalDNS の設定 (Helm chart)

```yaml
provider:
  name: webhook
  webhook:
    image:
      repository: ghcr.io/technotut/external-dns-fortigate-webhook
      tag: main
    env:
      - { name: FORTIGATE_URL, value: "https://192.168.99.129" }
      - { name: FORTIGATE_ZONE, value: svc.technotut.net }
      - { name: FORTIGATE_REVERSE_ZONES, value: 12.10.in-addr.arpa }
      - { name: FORTIGATE_INSECURE_SKIP_VERIFY, value: "true" }
      - name: FORTIGATE_TOKEN
        valueFrom:
          secretKeyRef: { name: external-dns-fortigate, key: token }
    livenessProbe:
      httpGet: { path: /healthz, port: http-webhook-metrics }
    readinessProbe:
      httpGet: { path: /readyz, port: http-webhook-metrics }
sources: [service, ingress, crd]
domainFilters: [svc.technotut.net]
policy: sync
registry: noop
managedRecordTypes: [A, AAAA, CNAME]
```

初めて動かすときは `DRY_RUN=true` にします。ログで書き込む内容を確かめてから外してください。

## 実機で確かめること (FortiOS 6.2)

テストは偽の FortiGate を相手にしています。FortiGate-100D (FortiOS 6.2.16) の実機では、次のことをまだ確かめていません。

- `Authorization: Bearer` ヘッダで認証できるか。できなければ `FORTIGATE_TOKEN_IN_QUERY=true` にします。
- PUT で `dns-entry` を渡すと、表全体が置き換わるか。
- CNAME の `canonical-name` と PTR の `hostname` は、末尾にドットを付けない FQDN で書いています。この形で正しく応答するか。

## 開発

```sh
go test ./...
podman build -t external-dns-fortigate-webhook -f Containerfile .
```

`main` に push するか `v*` のタグを付けると、GitHub Actions が `ghcr.io/technotut/external-dns-fortigate-webhook` にイメージを push します。クラスタ内のレジストリには置きません。DNS の webhook がクラスタ内のレジストリの名前解決に依存しないようにするためです。
