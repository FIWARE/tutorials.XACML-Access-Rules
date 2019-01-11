[![FIWARE Banner](https://fiware.github.io/tutorials.XACML-Access-Rules/img/fiware.png)](https://www.fiware.org/developers)

[![FIWARE Security](https://nexus.lab.fiware.org/repository/raw/public/badges/chapters/security.svg)](https://www.fiware.org/developers/catalogue/)
[![License: MIT](https://img.shields.io/github/license/fiware/tutorials.XACML-Access-Rules.svg)](https://opensource.org/licenses/MIT)
[![Support badge](https://nexus.lab.fiware.org/repository/raw/public/badges/stackoverflow/fiware.svg)](https://stackoverflow.com/questions/tagged/fiware)
[![FIWARE Security](https://img.shields.io/badge/XACML-3.0-ff7059.svg)](https://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html)
<br/>
[![Documentation](https://img.shields.io/readthedocs/fiware-tutorials.svg)](https://fiware-tutorials.rtfd.io)

このチュートリアルでは、追加のセキュリティ Generic Enabler の **Authzforce**
を紹介し、**Keyrock** によって生成されたセキュリティ・ルールにきめ細かい制御を
追加します。[以前のチュートリアル](https://github.com/Fiware/tutorials.PEP-Proxy)
で作成したエンティティへのアクセスは、XACML アクセス制御ポリシーを使用して構成
および制御されます。これにより、実行中にアップロードおよび再解釈できる柔軟な
ルールセットが作成されるため、複雑なビジネス・ルールを作成および変更できます。

チュートリアルでは、**Authzforce** を Web アプリケーションに統合する方法を示す
コードについて説明し、**Authzforce** XACML Server-PDP とのやり取りの例を示します
。[cUrl](https://ec.haxx.se/) コマンドは、Generic Enablers 間の相互作用を示す
ために使用されます。
[Postman documentation](https://fiware.github.io/tutorials.XACML-Access-Rules/)
が利用できます。

[![Run in Postman](https://run.pstmn.io/button.svg)](https://app.getpostman.com/run-collection/724e8e1ab1af11063d15)

# コンテンツ

<details>
<summary>詳細 <b>(クリックして拡大)</b></summary>

-   [ルールセットベースの権限](#ruleset-based-permissions)
    -   [XACML とは](#what-is-xacml)
-   [前提条件](#prerequisites)
    -   [Docker](#docker)
    -   [Cygwin](#cygwin)
-   [アーキテクチャ](#architecture)
    -   [Keyrock の設定](#keyrock-configuration)
    -   [PEP Proxy の設定](#pep-proxy-configuration)
    -   [Authzforce の設定](#authzforce-configuration)
    -   [チュートリアルのセキュリティ設定](#tutorial-security-configuration)
-   [起動](#start-up)
    -   [登場人物 (Dramatis Personae)](#dramatis-personae)
    -   [Authzforce - バージョン情報の取得](#authzforce---obtain-version-information)
-   [XACML サーバを使用](#using-an-xacml-server)
    -   [XACML ルールセットの読み込み](#reading-xacml-rulesets)
        -   [すべてのドメインをリスト](#two-list-all-domains)
        -   [単一ドメインを読み込み](#read-a-single-domain)
        -   [ドメイン内で利用可能なすべてのポリシーセットをリスト](#list-all-policysets-available-within-a-domain)
        -   [PolicySet の利用可能なリビジョンをリスト](#list-the-available-revisions-of-a-policyset)
        -   [PolicySet の単一バージョンを読み込む](#read-a-single-version-of-a-policyset)
    -   [ポリシー決定のリクエスト](#requesting-policy-decisions)
        -   [リソースへのアクセスを許可](#permit-access-to-a-resource)
        -   [リソースへのアクセスを拒否](#deny-access-to-a-resource)
-   [PDP - 高度な認可](#pdp---advanced-authorization)
    -   [高度な認可](#advanced-authorization)
        -   [ユーザがアクセス・トークンを取得](#user-obtains-an-access-token)
        -   [ロールとドメインを取得](#obtain-roles-and-domain)
        -   [ポリシーをリクエストに適用](#apply-a-policy-to-a-request)
        -   [高度な認可 - サンプル・コード](#advanced-authorization---sample-code)
        -   [高度な認可 - PEP Proxy](#advanced-authorization---pep-proxy)
    -   [PDP - 高度な許可 - 例の実行](#pdp---advanced-authorization---running-the-example)

</details>

<a name="ruleset-based-permissions"></a>

# ルールセットベースの権限

> "Say: Come, I will rehearse what _Allah_ hath prohibited you from:
>
> -   Join not anything as equal with _Him_
> -   Be good to your parents
> -   Kill not your children on a plea of want - _We_ provide sustenance for you
>     and for them
> -   Come not nigh to shameful deeds. Whether open or secret
> -   Take not life, which _Allah_ hath made sacred, except by way of justice
>     and law
>
> thus doth _He_ command you, that ye may learn wisdom."
>
> — Quran 6.151, Sūrat al-Anʻām

[以前のチュートリアル](https://github.com/Fiware/tutorials.Securing-Access)
では、認証に基づく単純なアクセス制御システム (レベル1)、またはロールに基づく
リソースへの基本的な認可アクセス (レベル2) を紹介しました。これらのポリシーは
簡単に作成できますが、その中のルールは非常に白と黒で、ルールを相互に依存したり、
例外条項を設定したり、期限や属性値に基づいてアクセスしたりすることはできません。
衝突が発生した場合に異なるルールを解決するメカニズムもありません。

複雑なアクセス制御シナリオを満たすには、追加の調停マイクロサービスが必要です。
これは、アクセス制御ルールの全セットを読んで解釈し、リクエストしているサービス
によって提供された証拠に基づいて、各許可/拒否ポリシー決定に関する判断を下すこと
ができます。

FIWARE [Authzforce](https://authzforce-ce-fiware.readthedocs.io/) は、
そのような解釈的なポリシー決定ポイント (PDP : Policy Decision Point) を提供する
ことができるサービスです。これは、
[XACML 標準](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=xacml)
を使用して提供されたルールを解釈できる高度なアクセス制御の Generic Enabler です
。ルールセットはいつでも修正およびアップロードでき、ビジネス・ニーズに応じて
変更できるセキュリティ・ポリシーを維持するための柔軟な方法を提供します。さらに、
アクセス・ポリシーを記述するために使用される言語は、非常に拡張性が高く、
あらゆるアクセス制御シナリオをカバーするように設計されています。

<a name="what-is-xacml"></a>

## XACML とは

eXtensible Access Control Markup Language (XACML) は、ベンダーに依存しない
宣言型アクセス制御ポリシー言語です。これは、一般的なアクセス制御の用語と
相互運用性を促進するために作成されました。ポリシー実行ポイント
(PEP : Policy Execution Point) やポリシー決定ポイント (PDP) などの要素の
アーキテクチャの命名ルールは、XACML 仕様に基づいています。

XACML ポリシーは、`<PolicySet>`, `<Policy>` と `<Rule>` の3つのレベルの
階層に分けられます。`<PolicySet>` は、それぞれが一つ以上の `<Rule>` 要素を
含む `<Policy>` 要素の集合です。

`<Policy>` 内の各 `<Rule>` は、それがリソースへのアクセスを許可すべきか
どうかに関して評価されます。総合的な `<Policy>` 結果は、順番に処理された
すべての `<Rule>` 要素の総合的な結果によって定義されます。そして、別々の
`<Policy>` 結果は、衝突の場合にどちらの `<Policy>` が勝つかを定義する
組み合わせアルゴリズムを使用してお互いに対して評価されます。

`<Rule>` 要素は `<Target>` と `<Condition>` から成ります。これは `<Rule>`
の例です。POST リクエストが `/bell/ring` エンドポイントに送信され、
`subject:role` に `role=security-role-0000-0000-000000000000` が提供されて
いれば、アクセスには、(`Effect="Permit"`) を与えられることを示しています。

```xml
<Rule RuleId="alrmbell-ring-0000-0000-000000000000" Effect="Permit">
  <Description>Ring Alarm Bell</Description>
  <Target>
    <AnyOf>
      <AllOf>
        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
          <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">/bell/ring</AttributeValue>
          <AttributeDesignator Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource" AttributeId="urn:thales:xacml:2.0:resource:sub-resource-id" DataType="http://www.w3.org/2001/XMLSchema#string" MustBePresent="true" />
        </Match>
      </AllOf>
    </AnyOf>
    <AnyOf>
      <AllOf>
        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
          <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">POST</AttributeValue>
          <AttributeDesignator Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action" AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id" DataType="http://www.w3.org/2001/XMLSchema#string" MustBePresent="true" />
        </Match>
      </AllOf>
    </AnyOf>
  </Target>
  <Condition>
    <Apply FunctionId="urn:oasis:names:tc:xacml:3.0:function:any-of">
      <Function FunctionId="urn:oasis:names:tc:xacml:1.0:function:string-equal" />
      <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">security-role-0000-0000-000000000000</AttributeValue>
      <AttributeDesignator Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject" AttributeId="urn:oasis:names:tc:xacml:2.0:subject:role" DataType="http://www.w3.org/2001/XMLSchema#string" MustBePresent="false" />
    </Apply>
  </Condition>
</Rule>
```

これは、XACML を使用した単純な Verb-Resource アクセス・ルールを作成するための
非常に冗長な方法ですが、単純な Verb-Resource ルールとは異なり、より複雑な
比較を行うことができます。たとえば、時刻が特定の時間より前であることを確認
したり、URL が特定の文字列で始まっていたり、特定の文字列を含んでいたりする
ことを確認します。条件は属性レベルまで指定することも、複雑な計算をするために
組み合わせることもできます。
たとえば、次のポリシーを適用するために XACML の `<Rule>` を作成できます。

> _ストア・マネージャは、月の初めにのみ商品の価格を修正することができます。
> また、直属の上司が最初に作成した商品の価格のみを変更することができます_

そのような `<Rule>` は、`<Condition>` が次のために別々の条項/明確化を
含むことを要求するでしょう :

-   ユーザのロールは何ですか？ (例 : `manager`)
-   どんなアクションが呼び出されていますか？ (例 : PATCH または PUT)
-   どのリソースが保護されている URL 文字列ですか。 (例 : `/v2/entities`)
-   リクエストのボディには他にどのような情報が必要ですか？
    (例 : エンティティ `type` は `Product` に等しくなければなりません)
-   リソースはいつリクエストされていますか？ (例 : 現在の日付)
-   リクエストを出す前に、他の場所から他にどのような追加情報を取得する
    必要がありますか
     -   誰がエンティティを作成しましたか？
         私ですか、それともマネージャ (上司) ですか？

ご覧のとおり、これらのルールはすぐに非常に複雑になることがあります。この
XACML の最初のイントロダクションでは、不要な混乱を避けるために使用される基本的
なルールセットはできるだけ単純に保ちます。XACML に基づくアクセスポリシーは、
複雑なシステムのセキュリティ・ニーズに合わせて拡張できると言うために十分です。

<a name="prerequisites"></a>

# 前提条件

<a name="docker"></a>

## Docker


物事を単純にするために、両方のコンポーネントが [Docker](https://www.docker.com)
を使用して実行されます。**Docker** は、さまざまコンポーネントをそれぞれの環境に
分離することを可能にするコンテナ・テクノロジです。

-   Docker Windows にインストールするには
    、[こちら](https://docs.docker.com/docker-for-windows/)の手順に従ってくださ
    い
-   Docker Mac にインストールするには
    、[こちら](https://docs.docker.com/docker-for-mac/)の手順に従ってください
-   Docker Linux にインストールするには
    、[こちら](https://docs.docker.com/install/)の手順に従ってください

**Docker Compose** は、マルチコンテナ Docker アプリケーションを定義して実行する
ためのツールです。
[YAML file](https://raw.githubusercontent.com/Fiware/tutorials.Identity-Management/master/docker-compose.yml)
ファイルは、アプリケーションのために必要なサービスを構成するために使用します。つ
まり、すべてのコンテナ・サービスは 1 つのコマンドで呼び出すことができます
。Docker Compose は、デフォルトで Docker for Windows と Docker for Mac の一部と
してインストールされますが、Linux ユーザは
[ここ](https://docs.docker.com/compose/install/)に記載されている手順に従う必要
があります。

<a name="cygwin"></a>

## Cygwin

シンプルな bash スクリプトを使用してサービスを開始します。Windows ユーザは
[cygwin](http://www.cygwin.com/) をダウンロードして、Windows 上の Linux
ディストリビューションと同様のコマンドライン機能を提供する必要があります。

<a name="architecture"></a>

# アーキテクチャ

このアプリケーションは、
[以前のチュートリアル](https://github.com/Fiware/tutorials.Securing-Access/)
で作成した既存の在庫管理 およびセンサ・ベースのアプリケーションにレベル3の
高度な認可のセキュリティを追加し、
[PEP Proxy](https://github.com/Fiware/tutorials.PEP-Proxy/) の背後にある
Context Broker へのアクセスを保護します。
[Orion Context Broker](https://fiware-orion.readthedocs.io/en/latest/),
[IoT Agent for UltraLight 2.0](https://fiware-iotagent-ul.readthedocs.io/en/latest/),
[Keyrock](https://fiware-idm.readthedocs.io/en/latest/) Identity Manager,
[Wilma](https://fiware-pep-proxy.readthedocs.io/en/latest/) PEP Proxy,
[Authzforce](https://authzforce-ce-fiware.readthedocs.io) XACML Server
の5つの​​ FIWARE コンポーネントを利用します。すべてのアクセス制御の決定は、
以前にアップロードされたポリシー・ドメインからルールセットを読み取る
**Authzforce** に委任されます。

Orion Context Brokerと IoT Agent はどちらも、オープンソースの
[MongoDB](https://www.mongodb.com/) テクノロジを使用して、保持している情報を
永続化します。また、
[以前のチュートリアル](https://github.com/Fiware/tutorials.IoT-Sensors/)
で作成したダミー IoT デバイスも使用します。**Keyrock** は、独自に
[MySQL](https://www.mysql.com/) データベースを使用しています。

したがって、アーキテクチャ全体は次の要素から構成されます :

-   FIWARE
    [Orion Context Broker](https://fiware-orion.readthedocs.io/en/latest/) は
    、[NGSI](https://fiware.github.io/specifications/ngsiv2/latest/) を使用
    してリクエストを受信します
-   FIWARE
    [IoT Agent for Ultralight 2.0](https://fiware-iotagent-ul.readthedocs.io/en/latest/)
    は、
    [Ultralight 2.0](https://fiware-iotagent-ul.readthedocs.io/en/latest/usermanual/index.html#user-programmers-manual)
    フォーマットのダミー IoT デバイスからノース・バウンドの測定値を受信し、
    Context Broker がコンテキスト・エンティティの状態を変更するための
    [NGSI](https://fiware.github.io/specifications/OpenAPI/ngsiv2)
    リクエストに変換します
-   FIWARE [Keyrock](https://fiware-idm.readthedocs.io/en/latest/) は、以下を含
    んだ、補完的な ID 管理システムを提供します :
    -   アプリケーションとユーザのための OAuth2 認証システム
    -   ID 管理のための Web サイトのグラフィカル・フロントエンド
    -   HTTP リクエストによる ID 管理用の同等の REST API
-   FIWARE
    [Authzforce](https://authzforce-ce-fiware.readthedocs.io/)
    **Orion** やチュートリアル・アプリケーションなどのリソースへのアクセスを
    保護する解釈可能な Policy Decision Point (PDP) を提供する XACML Server です
-   FIWARE
    [Wilma](https://fiware-pep-proxy.rtfd.io/)
    **Orion** マイクロサービスへのアクセスを保護する PEP Proxy プロキシです。
    認可決定の受渡しを **Authzforce** PDP に委任します
-   [MongoDB](https://www.mongodb.com/) データベース :
    -   **Orion Context Broker** が、データ・エンティティ、サブスクリプション、
        レジストレーションなどのコンテキスト・データ情報を保持するために使用しま
        す
    -   デバイスの URLs や Keys などのデバイス情報を保持するために **IoT Agent**
        によって使用されます
-   [MySQL](https://www.mysql.com/) データベース :
    -   ユーザ ID、アプリケーション、ロール、および権限を保持するために使用され
        ます
-   **在庫管理フロントエンド**には、次のことを行います :
    -   店舗情報を表示します
    -   各店舗でどの商品を購入できるかを示します
    -   ユーザが製品を"購入"して在庫数を減らすことができます
    -   許可されたユーザを制限されたエリアに入れることができます。認可の決定を
        **Authzforce** PDP に委任します
-   HTTP を介して実行されている
    [UltraLight 2.0](https://fiware-iotagent-ul.readthedocs.io/en/latest/usermanual/index.html#user-programmers-manual)
    プロトコルを使用す
    る[ダミー IoT デバイス](https://github.com/Fiware/tutorials.IoT-Sensors)のセ
    ットとして機能する Web サーバ。特定のリソースへのアクセスが制限されています
    。
要素間のやり取りはすべて HTTP リクエストによって開始されるため、
エンティティをコンテナ化して公開ポートから実行することができます。

![](https://fiware.github.io/tutorials.XACML-Access-Rules/img/architecture.png)

チュートリアルの各セクションの具体的なアーキテクチャについては、
以下で説明します。

<a name="keyrock-configuration"></a>

## Keyrock の設定

```yaml
keyrock:
    image: fiware/idm
    container_name: fiware-keyrock
    hostname: keyrock
    networks:
        default:
            ipv4_address: 172.18.1.5
    depends_on:
        - mysql-db
        - authzforce
    ports:
        - "3005:3005"
    environment:
        - DEBUG=idm:*
        - DATABASE_HOST=mysql-db
        - IDM_DB_PASS_FILE=/run/secrets/my_secret_data
        - IDM_DB_USER=root
        - IDM_HOST=http://localhost:3005
        - IDM_PORT=3005
        - IDM_ADMIN_USER=alice
        - IDM_ADMIN_EMAIL=alice-the-admin@test.com
        - IDM_ADMIN_PASS=test
        - IDM_PDP_LEVEL=advanced
        - IDM_AUTHZFORCE_ENABLED=true
        - IDM_AUTHZFORCE_HOST=authzforce
        - IDM_AUTHZFORCE_PORT=8080
    secrets:
        - my_secret_data
```


`keyrock` コンテナは、単一のポートでリッスンしている、Web
アプリケーション・サーバです :

-   ポート `3005` は HTTP トラフィック用に公開されているため、Web
    ページを表示して REST API で対話できます

`keyrock` コンテナは、**Authzforce** に接続していて、次のように、環境変数によって駆動されます。

| キー                   | 値           | 説明                                                                         |
| ---------------------- | ------------ | ---------------------------------------------------------------------------- |
| IDM_PDP_LEVEL          | `advanced`   | **Keyrock** が PDP の決定を Authzforce に委任すべきであることを示すフラグ    |
| IDM_AUTHZFORCE_ENABLED | `true`       | **Authzforce** が利用可能であることを示すフラグ                              |
| IDM_AUTHZFORCE_HOST    | `authzforce` | **Authzforce** の URL                                                         |
| IDM_AUTHZFORCE_PORT    | `8080`       | **Authzforce** がリッスンしているポート                                      |


YAML ファイルに記述されている他の `keyrock`
コンテナ設定値は以前のチュートリアルで説明されています。

<a name="pep-proxy-configuration"></a>

## PEP Proxy の設定

```yaml
orion-proxy:
    image: fiware/pep-proxy
    container_name: fiware-orion-proxy
    hostname: orion-proxy
    networks:
        default:
            ipv4_address: 172.18.1.10
    depends_on:
        - keyrock
        - authzforce
    ports:
        - "1027:1027"
    expose:
        - "1027"
    environment:
        - PEP_PROXY_APP_HOST=orion
        - PEP_PROXY_APP_PORT=1026
        - PEP_PROXY_PORT=1027
        - PEP_PROXY_IDM_HOST=keyrock
        - PEP_PROXY_HTTPS_ENABLED=false
        - PEP_PROXY_IDM_SSL_ENABLED=false
        - PEP_PROXY_IDM_PORT=3005
        - PEP_PROXY_APP_ID=tutorial-dckr-site-0000-xpresswebapp
        - PEP_PROXY_USERNAME=pep_proxy_00000000-0000-0000-0000-000000000000
        - PEP_PASSWORD=test
        - PEP_PROXY_PDP=authzforce
        - PEP_PROXY_AUTH_ENABLED=true
        - PEP_PROXY_MAGIC_KEY=1234
        - PEP_PROXY_AZF_PROTOCOL=http
        - PEP_PROXY_AZF_HOST=authzforce
        - PEP_PROXY_AZF_PORT=8080
```

`orion-proxy` コンテナは ポート `1027` でリッスンしている、FIWARE **Wilma** のインスタンスです。`orion` の ポート `1026` にトラフィックを転送するように設定されています。これは、Orion Context Broker が NGSI リクエストを待ち受けているデフォルト・ポートです。

`orion-proxy` コンテナは、PDP の決定を **Authzforce** を委任しており、次に示すように環境変数によって駆動されます。

| キー                   | 値           | 説明                                                                |
| ---------------------- | ------------ | ------------------------------------------------------------------- |
| PEP_PROXY_PDP          | `authzforce` | PEP Proxy が Authzforce を PDP として使用するようにするためのフラグ |
| PEP_PROXY_AZF_PROTOCOL | `http`       | **Authzforce** が使用するプロトコル                                 |
| PEP_PROXY_AZF_HOST     | `authzforce` | **Authzforce** の URL                                               |
| PEP_PROXY_AZF_PORT     | `8080`       | **Authzforce** がリッスンしているポート                             |

YAML ファイルに記述されている他の `orion-proxy` コンテナの設定値は、
以前のチュートリアルで説明されています。

<a name="authzforce-configuration"></a>

## Authzforce の設定

```yaml
authzforce:
    image: fiware/authzforce-ce-server
    hostname: authzforce
    container_name: fiware-authzforce
    networks:
        default:
            ipv4_address: 172.18.1.12
    ports:
        - "8080:8080"
    volumes:
        - ./authzforce/domains:/opt/authzforce-ce-server/data/domains
```

`authzforce` コンテナは、ポート `8080` で待機しています。これは PDP
の決定を行うためにリクエストを受け取ります。一連の XACML
アクセス制御ポリシーがすでに提供されているように、volume
は事前構成されたドメインをアップロードするために公開されています。

<a name="tutorial-security-configuration"></a>

## チュートリアルのセキュリティ設定

```yaml
tutorial:
    image: fiware/tutorials.context-provider
    hostname: tutorial
    container_name: fiware-tutorial
    networks:
        default:
            ipv4_address: 172.18.1.7
    expose:
        - "3000"
        - "3001"
    ports:
        - "3000:3000"
        - "3001:3001"
    environment:
        - "DEBUG=tutorial:*"
        - "WEB_APP_PORT=3000"
        - "KEYROCK_URL=http://localhost"
        - "KEYROCK_IP_ADDRESS=http://172.18.1.5"
        - "KEYROCK_PORT=3005"
        - "KEYROCK_CLIENT_ID=tutorial-dckr-site-0000-xpresswebapp"
        - "KEYROCK_CLIENT_SECRET=tutorial-dckr-site-0000-clientsecret"
        - "CALLBACK_URL=http://localhost:3000/login"
        - "AUTHZFORCE_ENABLED=true"
        - "AUTHZFORCE_URL=http://authzforce"
        - "AUTHZFORCE_PORT=8080"
```


`tutorial` コンテナは、2つのポートでリッスンしています :

-   ポート `3000` は公開されているため、Web ページにダミー
    IoT デバイスが表示されます
-   ポート `3001`は純粋にチュートリアル・アクセスのために公開されているので、
    cUrl や Postman は同じネットワークの一部でなくても Ultra Light
    コマンドを作成できます

`tutorial` コンテナは、**Authzforce** によってセキュリティが保護されており、
以下に示すように環境変数によって駆動されます。

| キー               | 値                  | 説明                                                |
| ------------------ | ------------------- | --------------------------------------------------- |
| AUTHZFORCE_ENABLED | `true`              | XACML PDP の使用を有効にするためのフラグ            |
| AUTHZFORCE_URL     | `http://authzforce` | **Authzforce** の URL                               |
| AUTHZFORCE_PORT    | `8080`              | **Authzforce** がリッスンしているポート             |


YAMLファイルに記述されている他の `tutorial` コンテナ設定値は
以前のチュートリアルで説明されています。

<a name="start-up"></a>

# 起動

インストールを開始するには、次の手順に従います :

```console
git clone git@github.com:Fiware/tutorials.XACML-Access-Rules.git
cd tutorials.XACML-Access-Rules

./services create
```

> **注:** Docker イメージの最初の作成には最大 3 分かかります

[services](https://github.com/Fiware/tutorials.XACML-Access-Rules/blob/master/services)
Bash スクリプトを実行することによって、コマンドラインからすべてのサービスを初期
化することができます :

```console
./services start
```

> :information_source: **注:** クリーンアップをやり直したい場合は、次のコマンド
> を使用して再起動することができます :
>
> ```console
> ./services stop
> ```

<a name="dramatis-personae"></a>

### 登場人物 (Dramatis Personae)

次の `test.com` のメンバは、合法的にアプリケーション内にアカウントを持っています

-   Alice, **Keyrock** アプリケーションの管理者です
-   Bob, スーパー・マーケット・チェーンの地域マネージャで、数人のマネージャがい
    ます :
    -   Manager1 (マネージャ 1)
    -   Manager2 (マネージャ 2)
-   Charlie, スーパー・マーケット・チェーンのセキュリティ責任者。彼の下に数人の
    警備員がいます :
    -   Detective1 (警備員 1)
    -   Detective2 (警備員 2)

次の`example.com` のメンバはアカウントにサインアップしましたが、アクセスを許可す
る理由はありません

-   Eve - 盗聴者のイブ
-   Mallory - 悪意のある攻撃者のマロリー
-   Rob - 強盗のロブ

<details>
  <summary>
   詳細<b>(クリックして拡大)</b>
  </summary>

| 名前       | E メール                  | パスワード |
| ---------- | ------------------------- | ---------- |
| alice      | alice-the-admin@test.com  | `test`     |
| bob        | bob-the-manager@test.com  | `test`     |
| charlie    | charlie-security@test.com | `test`     |
| manager1   | manager1@test.com         | `test`     |
| manager2   | manager2@test.com         | `test`     |
| detective1 | detective1@test.com       | `test`     |
| detective2 | detective2@test.com       | `test`     |


| 名前    | E メール            | パスワード |
| ------- | ------------------- | ---------- |
| eve     | eve@example.com     | `test`     |
| mallory | mallory@example.com | `test`     |
| rob     | rob@example.com     | `test`     |

</details>

<a name="authzforce---obtain-version-information"></a>

### Authzforce - バージョン情報の取得

**Authzforce** を実行すると、公開されている管理ポートに HTTP リクエストを
送信することでステータスを確認できます (通常 `8080`)。レスポンスがブランクの
場合、これは通常 **Authzforce** が実行されていないか別のポートで待機している
ためです。

#### :one: リクエスト

```console
curl -X GET \
  http://localhost:8080/authzforce-ce/version \
  -H 'Accept: application/xml'
```

#### レスポンス

レスポンスは **Authzforce** のバージョンに関する情報を返します。

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<productMetadata xmlns="http://authzforce.github.io/rest-api-model/xmlns/authz/5"
   xmlns:ns2="http://www.w3.org/2005/Atom"
   xmlns:ns3="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
   xmlns:ns4="http://authzforce.github.io/core/xmlns/pdp/6.0"
   xmlns:ns5="http://authzforce.github.io/pap-dao-flat-file/xmlns/properties/3.6"
   name="AuthzForce CE Server"
   version="8.0.1"
   release_date="2017-12-05"
   uptime="P0Y0M0DT0H8M47.642S"
   doc="https://authzforce.github.io/fiware/authorization-pdp-api-spec/5.2/"/>
```

<a name="using-an-xacml-server"></a>

# XACML サーバを使用

**Authzforce** は、ポリシー決定ポイント (PDP : Policy Decision Point)
Generic Enablerであり、
[XACML](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=xacml)
で書かれた `<PolicySet>` 情報に基づいて認可の決定を下します。
この例は、既存の一連のルールを含む実行中の XACML server から開始します。
XACML server は、ポリシーを管理し、アクセス制御ポリシー決定を呼び出すための
API を提供する必要があります。このチュートリアルは主に意思決定側に関係します。
アクセス制御ポリシーの作成と管理は後のチュートリアルで扱います。

<a name="reading-xacml-rulesets"></a>

## XACML ルールセットの読み込み

単一の XACML server を使用して、複数のアプリケーションに対するアクセス制御
ポリシーを管理できます。**Authzforce** は暗黙のうちにマルチテナントなって
います。つまり、別々の組織が互いから独立して彼らのポリシーを実現することが
できます。これは、各アプリケーションのセキュリティ・ポリシーを、別々の
**ドメイン** に分割し、そこでそれぞれ独自の `<PolicySets>` にアクセスできる
ようにすることで行います。ドメインは、セキュリティで保護されたアプリケーション
に関するメタデータとポリシー自体のバージョン (事実上、ファイル・サーバから
アクセスできる一連のファイル) を保持します。ドメイン管理 API を使用して、
提供されるドメインと保持されているポリシーについて **Authzforce**
に問い合わせることができます。

<a name="two-list-all-domains"></a>

### すべてのドメインをリスト

**Authzforce** にドメイン情報をリクエストするには、
`/authzforce-ce/domains` エンドポイントにリクエストを出します。

#### :two: リクエスト

```console
curl -X GET \
  http://localhost:8080/authzforce-ce/domains
```

#### レスポンス

レスポンスには、**Authzforce** で利用可能なドメインがリストされます。これは
起動時に **Authzforce** にアップロードされたディレクトリ構造に対応します。

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<resources xmlns="http://authzforce.github.io/rest-api-model/xmlns/authz/5"
  xmlns:ns2="http://www.w3.org/2005/Atom"
  xmlns:ns3="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
  xmlns:ns4="http://authzforce.github.io/core/xmlns/pdp/6.0"
  xmlns:ns5="http://authzforce.github.io/pap-dao-flat-file/xmlns/properties/3.6">
    <ns2:link rel="item" href="gQqnLOnIEeiBFQJCrBIBDA" title="gQqnLOnIEeiBFQJCrBIBDA"/>
</resources>
```

<a name="read-a-single-domain"></a>

### 単一ドメインを読み込み

ドメインに関する情報を読み、さらに詳しく調べるには、
`authzforce-ce/domains/{{domain-id}}` エンドポイントにリクエストを出します。
次のリクエストでは、外部の Policy Administration Point によってランダム・キーを
使用して生成された `gQqnLOnIEeiBFQJCrBIBDA` ドメインに関する情報が取得されます。
この場合、**Keyrock** が PAP として使用され、
ルールセットが事前に生成されています。

#### :three: リクエスト

```console
curl -X GET \
  http://localhost:8080/authzforce-ce/domains/gQqnLOnIEeiBFQJCrBIBDA
```

#### レスポンス

レスポンスには、**Keyrock** (`tutorial-dckr-site-0000-xpresswebapp`)
内で使用されている id など、ドメインに関する詳細情報がリストされます。

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<domain xmlns="http://authzforce.github.io/rest-api-model/xmlns/authz/5"
  xmlns:ns2="http://www.w3.org/2005/Atom"
  xmlns:ns3="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
  xmlns:ns4="http://authzforce.github.io/core/xmlns/pdp/6.0"
  xmlns:ns5="http://authzforce.github.io/pap-dao-flat-file/xmlns/properties/3.6">
    <properties externalId="tutorial-dckr-site-0000-xpresswebapp"/>
    <childResources>
        <ns2:link rel="item" href="/properties" title="Domain properties"/>
        <ns2:link rel="item" href="/pap" title="Policy Administration Point"/>
        <ns2:link rel="http://docs.oasis-open.org/ns/xacml/relation/pdp"
          href="/pdp" title="Policy Decision Point"/>
    </childResources>
</domain>
```

<a name="list-all-policysets-available-within-a-domain"></a>

### ドメイン内で利用可能なすべてのポリシーセットをリスト

ドメイン内で見つかったすべての PolicySets に対して生成された ids をリストする
には、`authzforce-ce/domains/{{domain-id}}/pap/policies` エンドポイントに
リクエストを出します。次のリクエストは、`gQqnLOnIEeiBFQJCrBIBDA`
ドメイン内で見つかった特定ポリシーの ids のリストを取得します。

#### :four: リクエスト

```console
curl -X GET \
  http://localhost:8080/authzforce-ce/domains/gQqnLOnIEeiBFQJCrBIBDA/pap/policies
```

#### レスポンス

レスポンスは、**Authzforce** コンテナ内で利用可能な、指定されたポリシーの
利用可能なリビジョンのリストを返します。これは、`1.xml`, `2.xml`
などの名前付き XML ファイルに対応します。

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<resources xmlns="http://authzforce.github.io/rest-api-model/xmlns/authz/5"
  xmlns:ns2="http://www.w3.org/2005/Atom"
  xmlns:ns3="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
  xmlns:ns4="http://authzforce.github.io/core/xmlns/pdp/6.0"
  xmlns:ns5="http://authzforce.github.io/pap-dao-flat-file/xmlns/properties/3.6">
    <ns2:link rel="item" href="f8194af5-8a07-486a-9581-c1f05d05483c"/>
    <ns2:link rel="item" href="root"/>
</resources>
```

<a name="list-the-available-revisions-of-a-policyset"></a>

### PolicySet の利用可能なリビジョンをリスト

ポリシーの利用可能なリビジョンをリストするには、
`authzforce-ce/domains/{{domain-id}}/pap/policies/{{policy-id}}`
エンドポイントにリクエストを出します。使用可能なポリシー id はランダムに
生成され、前のリクエストを使用してドリル・ダウンすることによって取得できます。
次のリクエストは、`gQqnLOnIEeiBFQJCrBIBDA` ドメイン内で見つかった特定ポリシー
のリビジョンのリストを取得します。

#### :five: リクエスト

```console
curl -X GET \
  http://localhost:8080/authzforce-ce/domains/gQqnLOnIEeiBFQJCrBIBDA/pap/policies/f8194af5-8a07-486a-9581-c1f05d05483c
```

#### レスポンス

レスポンスは、**Authzforce** コンテナ内で利用可能な、指定されたポリシーの
利用可能なリビジョンのリストを返します。これは、`1.xml`, `2.xml`
などの名前付き XML ファイルに対応します。

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<resources xmlns="http://authzforce.github.io/rest-api-model/xmlns/authz/5"
  xmlns:ns2="http://www.w3.org/2005/Atom"
  xmlns:ns3="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
  xmlns:ns4="http://authzforce.github.io/core/xmlns/pdp/6.0"
  xmlns:ns5="http://authzforce.github.io/pap-dao-flat-file/xmlns/properties/3.6">
    <ns2:link rel="item" href="2"/>
    <ns2:link rel="item" href="1"/>
</resources>
```

<a name="read-a-single-version-of-a-policyset"></a>

### PolicySet の単一バージョンを読み込む

`<PolicySet>` の単一のリビジョンを取得するには、
`authzforce-ce/domains/{{domain-id}}/pap/policies/{{policy-id}}/{{revision-number}}`
エンドポイントにリクエストを出します。次のリクエストは、`gQqnLOnIEeiBFQJCrBIBDA`
ドメイン内で見つかった特定のポリシーの2番目のリビジョンを取得します。

#### :six: リクエスト

```console
curl -X GET \
  http://localhost:8080/authzforce-ce/domains/gQqnLOnIEeiBFQJCrBIBDA/pap/policies/f8194af5-8a07-486a-9581-c1f05d05483c/2
```

#### レスポンス

レスポンスには、与えられたリビジョンのフルの `<PolicySet>` が含まれています。
これは **Authzforce** 内に保持されている
[ファイル](https://github.com/Fiware/tutorials.XACML-Access-Rules/blob/master/authzforce/domains/gQqnLOnIEeiBFQJCrBIBDA/policies/ZjgxOTRhZjUtOGEwNy00ODZhLTk1ODEtYzFmMDVkMDU0ODNj/2.xml)
のコピーです 。

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ns3:PolicySet xmlns="http://authzforce.github.io/rest-api-model/xmlns/authz/5"
  xmlns:ns2="http://www.w3.org/2005/Atom"
  xmlns:ns3="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
  xmlns:ns4="http://authzforce.github.io/core/xmlns/pdp/6.0"
  xmlns:ns5="http://authzforce.github.io/pap-dao-flat-file/xmlns/properties/3.6" PolicySetId="f8194af5-8a07-486a-9581-c1f05d05483c" Version="2" PolicyCombiningAlgId="urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:deny-unless-permit">
    <ns3:Description>Policy Set for application tutorial-dckr-site-0000-xpresswebapp</ns3:Description>
    <ns3:Target/>
    <ns3:Policy PolicyId="security-role-0000-0000-000000000000"
      Version="1.0"
      RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit">
        <ns3:Description>Role security-role-0000-0000-000000000000 from application tutorial-dckr-site-0000-xpresswebapp</ns3:Description>
        <ns3:Target>
           ...etc
        </ns3:Target>
        <ns3:Rule RuleId="alrmbell-ring-0000-0000-000000000000" Effect="Permit">
            ...etc
        </ns3:Rule>
        ..etc
    </ns3:Policy>
</ns3:PolicySet>
```

<a name="requesting-policy-decisions"></a>

## ポリシー決定のリクエスト

このチュートリアルの目的のために、**Authzforce** には、以前の Securing Access
チュートリアルに見られるレベル2の認可の例と同様に、
単純な基本的なロール・ベースのルールのシンプル・セットが提供されています。

-   ドアのロック解除コマンドは、**セキュリティ**・スタッフのみが送信できます
-   価格変更およびオーダー在庫エリアへのアクセスは、**マネージャ**だけが
    可能です
-   **マネージャ**または**セキュリティ**のロールを持つ人は、ベルを鳴らすこと
    ができます
-   **マネージャ**と**セキュリティ**の両方がストア・データにアクセスして
    インタラクトすることができます。

唯一の違いは、すべてのストア・エンティティへのアクセスが、レベル1認証アクセス
に基づくのではなく、割り当てられたロールを持つユーザに制限されるように
なったことです。

**Authzforce** に決定をリクエストするには、すべての関連情報を含む
構造化リクエストを `domains/{domain-id}/pdp` エンドポイントに送信する必要が
あります。この場合、リクエストのボディには、ユーザが持つロール、リクエスト
されているアプリケーション id  (`tutorial-dckr-site-0000-xpresswebapp`)、
リクエストされている HTTP 動詞とリソース (`/app/price-change` URL に対する
GET リクエスト) などの情報が含まれています。明らかに、ボディで渡される情報は、
ルールが複雑になるにつれて拡張できます。

<a name="permit-access-to-a-resource"></a>

### リソースへのアクセスを許可

**Authzforce** に決定をリクエストするには、`domains/{domain-id}/pdp`
エンドポイントに POST リクエストを出します。この場合、ユーザは
`managers-role-0000-0000-000000000000` を持ち、
リソース `/app/price-change` へのアクセスをリクエストしています。

#### :seven: リクエスト

```console
curl -X POST \
  http://localhost:8080/authzforce-ce/domains/gQqnLOnIEeiBFQJCrBIBDA/pdp \
  -H 'Content-Type: application/xml' \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<Request xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" CombinedDecision="false" ReturnPolicyIdList="false">
   <Attributes Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject">
      <Attribute AttributeId="urn:oasis:names:tc:xacml:2.0:subject:role" IncludeInResult="false">
         <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">managers-role-0000-0000-000000000000</AttributeValue>
      </Attribute>
   </Attributes>
   <Attributes Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource">
      <Attribute AttributeId="urn:oasis:names:tc:xacml:1.0:resource:resource-id" IncludeInResult="false">
         <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">tutorial-dckr-site-0000-xpresswebapp</AttributeValue>
      </Attribute>
      <Attribute AttributeId="urn:thales:xacml:2.0:resource:sub-resource-id" IncludeInResult="false">
         <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">/app/price-change</AttributeValue>
      </Attribute>
   </Attributes>
   <Attributes Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action">
      <Attribute AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id" IncludeInResult="false">
         <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">GET</AttributeValue>
      </Attribute>
   </Attributes>
   <Attributes Category="urn:oasis:names:tc:xacml:3.0:attribute-category:environment" />
</Request>'
```

#### レスポンス

`managers-role-0000-0000-000000000000` は `/app/price-change`
エンドポイントへのアクセスを許可します。成功したリクエストに対するレスポンスは
リソースへのアクセスを許可するための `<Decision>` 要素を含みます。

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ns3:Response xmlns="http://authzforce.github.io/rest-api-model/xmlns/authz/5"
  xmlns:ns2="http://www.w3.org/2005/Atom"
  xmlns:ns3="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
  xmlns:ns4="http://authzforce.github.io/core/xmlns/pdp/6.0"
  xmlns:ns5="http://authzforce.github.io/pap-dao-flat-file/xmlns/properties/3.6">
    <ns3:Result>
        <ns3:Decision>Permit</ns3:Decision>
    </ns3:Result>
</ns3:Response>
```

<a name="deny-access-to-a-resource"></a>

### リソースへのアクセスを拒否

**Authzforce** に決定をリクエストするには、
`domains/{domain-id}/pdp` エンドポイントに POST リクエストを
出します。この場合、ユーザは `security-role-0000-0000-000000000000`
を持ち、リソース `/app/price-change` へのアクセスをリクエスト
しています。

#### :eight: リクエスト

```console
curl -X POST \
  http://localhost:8080/authzforce-ce/domains/gQqnLOnIEeiBFQJCrBIBDA/pdp \
  -H 'Content-Type: application/xml' \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<Request xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" CombinedDecision="false" ReturnPolicyIdList="false">
   <Attributes Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject">
      <Attribute AttributeId="urn:oasis:names:tc:xacml:2.0:subject:role" IncludeInResult="false">
         <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">security-role-0000-0000-000000000000</AttributeValue>
      </Attribute>
   </Attributes>
   <Attributes Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource">
      <Attribute AttributeId="urn:oasis:names:tc:xacml:1.0:resource:resource-id" IncludeInResult="false">
         <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">tutorial-dckr-site-0000-xpresswebapp</AttributeValue>
      </Attribute>
      <Attribute AttributeId="urn:thales:xacml:2.0:resource:sub-resource-id" IncludeInResult="false">
         <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">/app/price-change</AttributeValue>
      </Attribute>
   </Attributes>
   <Attributes Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action">
      <Attribute AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id" IncludeInResult="false">
         <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">GET</AttributeValue>
      </Attribute>
   </Attributes>
   <Attributes Category="urn:oasis:names:tc:xacml:3.0:attribute-category:environment" />
</Request>'
```

#### レスポンス

`security-role-0000-0000-000000000000` は、 `/app/price-change` エンドポイント
へのアクセスを許可しません。失敗したリクエストに対するレスポンスには、
リソースへのアクセスを `Deny` (拒否) する `<Decision>` 要素が含まれています。

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ns3:Response xmlns="http://authzforce.github.io/rest-api-model/xmlns/authz/5"
  xmlns:ns2="http://www.w3.org/2005/Atom"
  xmlns:ns3="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
  xmlns:ns4="http://authzforce.github.io/core/xmlns/pdp/6.0"
  xmlns:ns5="http://authzforce.github.io/pap-dao-flat-file/xmlns/properties/3.6">
    <ns3:Result>
        <ns3:Decision>Deny</ns3:Decision>
    </ns3:Result>
</ns3:Response>
```

<a name="pdp---advanced-authorization"></a>

# PDP - 高度な認可


復習ですが、PDP アクセス制御には3つのレベルがあります。

-   レベル1 :認証アクセス - サイン・インしているすべてのユーザにすべての
    アクションを許可し、匿名ユーザにはアクションを許可しません
-   レベル2 :基本認可 - 現在ログインしているユーザがアクセスできるリソース
    と動詞を確認します
-   レベル3 :高度な認可 - [XACML](https://en.wikipedia.org/wiki/XACML) に
    よるきめ細かい制御をします

FIWARE では、スマート・アプリケーション・インフラストラクチャ内の既存の
セキュリティ・マイクロサービス (IDM および PEP Proxy) に **Authzforce** を
追加することで、レベル3のアクセス制御を提供できます。アクセス制御レベル1と2は、
[以前のチュートリアル](https://github.com/Fiware/tutorials.Securing-Access)
で取り上げてきましたが、**Keyrock** を単独で使用して、関連する PEP Proxy
を使用してもしなくても実行できます。

<a name="advanced-authorization"></a>

## 高度な認可


高度な認可 (Advanced Authorization) は複雑なルールセットを扱うことができます。
権限は、もはや固定のロール、リソース、およびアクションに基づいているだけでなく、
必要に応じて拡張することもできます。

たとえば、ロール `XXX` のユーザは、HTTP 動詞が `GET`, `PUT`, `POST` の
**いずれか**であれば、`YYY` **で始まる** URL にアクセスできます。
そのようなユーザは、彼らがそもそも作成者であることを**条件として**
`DELETE` を実行することもできます。

チュートリアルのプログラム例の中で私たちは **Keyrock** の私達の自身の信頼された
インスタンスを使用しています。一度ユーザがサインインして `access_token`
を取得すると、`access_token` はセッションに保存されリクエストに応じてユーザの
詳細を取得するために使われます。Orion Context Broker へのすべてのアクセスは、
PEP Proxy の背後に隠されています。リクエストが Orion に行われるたびに、
`access_token` がリクエストのヘッダで渡され、PEP Proxy がそのリクエストを
実行するかどうかの決定を処理します。

<a name="user-obtains-an-access-token"></a>

### ユーザがアクセス・トークンを取得

自分自身を識別するためには、すべてのユーザがアクセス・トークンを
取得する必要があります。そのためには、
[以前のチュートリアル](https://github.com/Fiware/tutorials.Securing-Access)
で説明した OAuth2 アクセス許可のいずれかを使用する必要があります。

ユーザ資格情報フローを使用してログインするには、`grant_type=password`
を指定して **Keyrock** の `oauth2/token` エンドポイントに POST
リクエストを送信します。

#### :nine: リクエスト

```console
curl -X POST \
  http://localhost:3005/oauth2/token \
  -H 'Accept: application/json' \
  -H 'Authorization: Basic dHV0b3JpYWwtZGNrci1zaXRlLTAwMDAteHByZXNzd2ViYXBwOnR1dG9yaWFsLWRja3Itc2l0ZS0wMDAwLWNsaWVudHNlY3JldA==' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=bob-the-manager@test.com&password=test&grant_type=password'
```

#### レスポンス

レスポンスはユーザを識別するために `access_token` を返します
(この場合は Bob マネージャ)

```json
{
    "access_token": "08fef363c429cb34cfff3f56dfe751a8d1890690",
    "token_type": "Bearer",
    "expires_in": 3599,
    "refresh_token": "35a644094b598cb0d720fcb323369a53820a6a44",
    "scope": ["bearer"]
}
```

<a name="obtain-roles-and-domain"></a>

### ロールとドメインを取得

ユーザがログインしている場合、`access_token` は `/user` エンドポイントと組み合わせて
リソースへのアクセス許可を得るために使用できます。
この例では、特定のリソースに対する Bob の権限を取得します。

#### :one::zero: リクエスト

```console
curl -X GET \
  'http://localhost:3005/user?access_token={{access_token}}&app_id={{app-id}}&authzforce=true'
```

ここで :

-   `{{access-token}}` は、ログインしているユーザの現在のアクセス・トークンです
    (例 : `08fef363c429cb34cfff3f56dfe751a8d1890690`)
-   `{{app-id}}` は `tutorial-dckr-site-0000-xpresswebapp` をリクエストする
    アプリケーションを保持し、`authzforce=true` は **Keyrock** から
    **Authzforce** ドメインを取得したいことを示します

#### レスポンス

レスポンスには、リクエストへの直接アクセスを拒否する `authorization_decision`
属性を含みますが、追加のリクエストが **Authzforce** からの決定になるように
追加の情報が含まれています。

以下の例では、使用されたアクセス・トークンはマネージャの Bob に属し、
そのロールと `app-id` に関連付けられた `app_azf_domain` が返されます。

```json
{
    "organizations": [],
    "displayName": "",
    "roles": [
        {
            "id": "managers-role-0000-0000-000000000000",
            "name": "Management"
        }
    ],
    "app_id": "tutorial-dckr-site-0000-xpresswebapp",
    "trusted_apps": [],
    "isGravatarEnabled": false,
    "email": "bob-the-manager@test.com",
    "id": "bbbbbbbb-good-0000-0000-000000000000",
    "authorization_decision": "",
    "app_azf_domain": "gQqnLOnIEeiBFQJCrBIBDA",
    "eidas_profile": {},
    "username": "bob"
}
```

<a name="apply-a-policy-to-a-request"></a>

### ポリシーをリクエストに適用

**Authzforce** に決定をリクエストするには、すべての関連情報を含む構造化
リクエストを `domains/{domain-id}/pdp` エンドポイントに送信する必要があります。
この場合、リクエストのボディには、ユーザが持つロール
(`managers-role-0000-0000-000000000000`)、リクエストされているアプリケーション
id (`tutorial-dckr-site-0000-xpresswebapp`)、リクエストされている HTTP 動詞と
リソース (`/v2/entities` URL に対する POST リクエスト) などの情報が含まれます。

#### :one::one: リクエスト

```console
curl -X POST \
  http://localhost:8080/authzforce-ce/domains/gQqnLOnIEeiBFQJCrBIBDA/pdp \
  -H 'Content-Type: application/xml' \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<Request xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" CombinedDecision="false" ReturnPolicyIdList="false">
   <Attributes Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject">
      <Attribute AttributeId="urn:oasis:names:tc:xacml:2.0:subject:role" IncludeInResult="false">
         <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">managers-role-0000-0000-000000000000</AttributeValue>
      </Attribute>
   </Attributes>
   <Attributes Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource">
      <Attribute AttributeId="urn:oasis:names:tc:xacml:1.0:resource:resource-id" IncludeInResult="false">
         <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">tutorial-dckr-site-0000-xpresswebapp</AttributeValue>
      </Attribute>
      <Attribute AttributeId="urn:thales:xacml:2.0:resource:sub-resource-id" IncludeInResult="false">
         <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">/v2/entities</AttributeValue>
      </Attribute>
   </Attributes>
   <Attributes Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action">
      <Attribute AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id" IncludeInResult="false">
         <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">POST</AttributeValue>
      </Attribute>
   </Attributes>
   <Attributes Category="urn:oasis:names:tc:xacml:3.0:attribute-category:environment" />
</Request>'
```

#### レスポンス

レスポンスには、リクエストを `Permit` (許可) または `Deny` (拒否)するための
`<Decision>` 要素が含まれています。

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ns3:Response xmlns="http://authzforce.github.io/rest-api-model/xmlns/authz/5"
  xmlns:ns2="http://www.w3.org/2005/Atom"
  xmlns:ns3="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
  xmlns:ns4="http://authzforce.github.io/core/xmlns/pdp/6.0"
  xmlns:ns5="http://authzforce.github.io/pap-dao-flat-file/xmlns/properties/3.6">
    <ns3:Result>
        <ns3:Decision>Permit</ns3:Decision>
    </ns3:Result>
</ns3:Response>
```

<a name="advanced-authorization---sample-code"></a>

### 高度な認可 - サンプル・コード

プログラム的には、Policy Execution Point は2つの部分から構成されます。
Keyrock に対する OAuth リクエストは、ユーザに関する情報
(割り当てられたロールなど) と、照会されるポリシー・ドメインを取得します。

2番目のリクエストが Authzforce 内の関連ドメイン・エンドポイントに送信され、
Authzforce が判断を下すために必要なすべての情報が提供されます。Authzforce
は **permit** (許可) または **deny** (拒否) のレスポンスで応答し、
続行するかどうかの決定はその後行うことができます。

```javascript
function authorizeAdvancedXACML(req, res, next, resource = req.url) {
    const keyrockUserUrl =
        "http://keyrock/user?access_token=" +
        req.session.access_token +
        "&app_id=" +
        clientId +
        "&authzforce=true";

    return oa
        .get(keyrockUserUrl)
        .then(response => {
            const user = JSON.parse(response);
            return azf.policyDomainRequest(
                user.app_azf_domain,
                user.roles,
                resource,
                req.method
            );
        })
        .then(authzforceResponse => {
            res.locals.authorized = authzforceResponse === "Permit";
            return next();
        })
        .catch(error => {
            debug(error);
            res.locals.authorized = false;
            return next();
        });
}
```

各リクエストを Authzforce に提供するための完全なコードはチュートリアルの
[Git リポジトリ](https://github.com/Fiware/tutorials.Step-by-Step/blob/master/context-provider/lib/azf.js)
にあります。提供する実際の情報はビジネス・ユースケースに依存します。
一時的な情報、レコード間の関係などを含むように拡張できます。
非常に単純な例ではロールだけが必要です。

```javascript
const xml2js = require("xml2js");
const request = require("request");

function policyDomainRequest(domain, roles, resource, action) {
    let body =
        '<?xml version="1.0" encoding="UTF-8"?>\n' +
        '<Request xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" CombinedDecision="false" ReturnPolicyIdList="false">\n';
    // Code to create the XML body for the request is omitted
    body = body + "</Request>";

    const options = {
        method: "POST",
        url: "http://authzforceUrl/authzforce-ce/domains/" + domain + "/pdp",
        headers: { "Content-Type": "application/xml" },
        body
    };

    return new Promise((resolve, reject) => {
        request(options, function(error, response, body) {
            let decision;
            xml2js.parseString(
                body,
                { tagNameProcessors: [xml2js.processors.stripPrefix] },
                function(err, jsonRes) {
                    // The decision is found within the /Response/Result[0]/Decision[0] XPath
                    decision = jsonRes.Response.Result[0].Decision[0];
                }
            );
            decision = String(decision);
            return error ? reject(error) : resolve(decision);
        });
    });
}
```

<a name="advanced-authorization---pep-proxy"></a>

### 高度な認可 - PEP Proxy

PEP Proxy 内で高度な認証を適用するには、上記のプログラム例と非常によく似た
コードが必要です。**Wilma** Generic Enablerは、リクエストによって供給される
ヘッダからトークンを抽出し、リクエスト行う **Keyrock** ユーザに関するさらなる
情報を得るために。次に PDP リクエストが**Authzforce** に対して行われ、
続行するかどうかが決定されます。

明らかに、スケーラブルなソリューションであれば、不要なリクエストを避けるために、
行われた PDP リクエストとレスポンスに関する情報もキャッシュする必要があります。

<a name="pdp---advanced-authorization---running-the-example"></a>

## PDP - 高度な許可 - 例の実行

> **注** レベル3では5つのリソースが確保されています :
>
> -   ドアのロック解除コマンドを送信
> -   ring bell コマンドを送信
> -   価格変更エリアへのアクセス
> -   オーダー在庫エリアへのアクセス
> -   Orion へのアクセス (PEP Proxy の背後)

#### Eve 盗聴者

Eve はアカウントを持っていますが、アプリケーション内にロールはありません。

> **注** Eve は認識されたアカウントを持っているので、完全な認証アクセスを
> 得ます。これは、自分のアカウントにロールがアタッチされていなくても、
> 自分がストア・ページを_view_ (表示) できることを意味します。

-   `http://localhost:3000`から、`eve@example.com` として、パスワード
    `test`　でログインします

##### レベル 3 : 高度な認可アクセス

-   ストア・ページをクリック - ログインしたユーザはそのページを見るための
    アクセスを許可されますが、Eve にはアクセスを許可するロールがないため、
    Orion データを取得するためのアクセスは**拒否**されます

-   `http://localhost:3000` で制限されたアクセス・リンクをクリック -
    アクセスは**拒否**されます
-   `http://localhost:3000/device/monitor` でデバイス・モニタをオープン
    -   ドアのロックを解除 - アクセスは**拒否**されます
    -   ベルを鳴らす - アクセスは**拒否**されます

#### Bob 地域マネージャ

Bob は、**management** ロールを持っています

-   `http://localhost:3000` から、`bob-the-manager@test.com` として、
    パスワード `test` でログインします

##### レベル 3 : 高度な認可アクセス

-   `http://localhost:3000` で制限されたアクセス・リンクをクリック -
    アクセスは**許可**されます - これは management のみの権限です
-   `http://localhost:3000/device/monitor` でデバイス・モニタを開きます
    -   ドアのロックを解除 - アクセスは**拒否**されます -
        これは security のみの許可です
    -   ベルを鳴らす - アクセスは**許可**されます -
        これは management ユーザに許可されます

#### Charlie セキュリティ・マネージャ

Charlie は、the **security** ロールを持っています

-   `http://localhost:3000` から、`charlie-security@test.com` として、
    パスワード `test` でログインします

##### Level 3: Advanced Authorization Access

-   `http://localhost:3000` で制限されたアクセス・リンクをクリック -
    アクセスは**拒否**されます - これは management のみの権限です
-   `http://localhost:3000/device/monitor` でデバイス・モニタを開きます
    -   ドアのロックを解除 - アクセスは**許可**されます -
        これは security のみの許可です
    -   ベルを鳴らす - アクセスが**許可**されます -
        これは security ユーザに許可されます

# 次のステップ

高度な機能を追加することで、アプリケーションに複雑さを加える方法を知りたいですか
？このシリーズの
[他のチュートリアル](https://www.letsfiware.jp/fiware-tutorials)を
読むことで見つけることができます。

---

## License

[MIT](LICENSE) © 2018-2019 FIWARE Foundation e.V.
