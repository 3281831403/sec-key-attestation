设备密钥做了远程证明，伪造一份证明链就能把别人的密钥登记成自己的：被签名载荷只含 nonce 而不含公钥摘要，换公钥后旧签名仍可复用；签名比较使用普通等号而非恒定时间比较；链校验只验证叶子而不逐级验证父签名；链深度按报价条数计算且缺失父级不报错；绑定校验只比较 nonce 前缀而不校验公钥；时效只校验终止时间而接受尚未生效的证明；登记不检查已有登记者而允许覆盖他人密钥；登记不幂等而同一密钥重复登记返回不同结果；吊销只删除主记录而链上引用仍可用；批量校验复用链上下文而第二个请求沿用第一个请求的父键。attest/chain.py 是核心，tests/test_chain.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

# 设备密钥远程证明链

这是一个只改实现、不改测试的安全 Bugfix 题。考生需要让一条伪造的远程证明链无法把攻击者的公钥登记成其他设备的密钥，并保证登记、重放、吊销与批量校验的语义同时成立。

## 目录与导入布局

```text
sec-key-attestation/
  README.md
  pyproject.toml
  src/attest/__init__.py
  src/attest/chain.py
  tests/test_chain.py
```

项目采用 src 布局。pyproject.toml 中的 pytest 配置为：

```toml
[tool.pytest.ini_options]
pythonpath = ["src"]
testpaths = ["tests"]
```

因此不需要安装包，也不依赖任何第三方运行库；在仓库根目录执行测试即可导入 attest 包。

## 运行方式

在仓库根目录运行：

```text
python -m pytest tests -q
```

初始状态应当恰好是：

```text
15 failed
```

15 个失败必须全部来自 8 个未实现桩抛出的 NotImplementedError。实现完成后，同一命令应当得到 15 passed。

## 数据模型与签名约定

一条报价 link 是字典，字段如下：

| 字段 | 含义 |
| --- | --- |
| key_id | public_key 的小写 SHA-256 十六进制摘要 |
| public_key | 公钥字节 |
| nonce | 本次挑战的随机字节串 |
| pcr_digest | 平台配置摘要字节 |
| owner | 非空登记主体字符串 |
| issued_at | 生效时间，整数 Unix 秒，包含端点 |
| expires_at | 失效时间，整数 Unix 秒，包含端点 |
| parent | 父 link 字典；根为 None |
| parent_key_id | 父 link 的 key_id；根为 None |
| signature | HMAC-SHA256 签名字节 |

签名约定是 HMAC-SHA256(parent_key, quote_payload(nonce, key_id, pcr_digest))。根 link 用自身 public_key 自签，子 link 用父 link 的 public_key 验签。完整证明是带嵌套 parent 的叶子 link；扁平链按根到叶排列。

register 成功时写入的记录包含 key_id、public_key、owner、quote、registered_at、chain、revoked。chain 是根到叶的 key_id 列表。nonce 首次使用记录在 store 的 __nonces__ 子字典中，吊销不清理该账本。

## 8 个桩

1. quote_payload：生成被签名载荷，必须覆盖 nonce 与公钥摘要。
2. verify_link：单级签名校验，必须使用 hmac.compare_digest。
3. chain_depth：校验根到叶的父子链接并返回深度，缺父级必须抛 ValueError。
4. binding_ok：精确匹配完整 nonce，并核对公钥及其摘要。
5. freshness_ok：生效与失效两端都包含，证明总寿命超过 window 必须拒绝。
6. register：验证完整链后登记，幂等，拒绝他人覆盖，拒绝 nonce 重放。
7. revoke：删除目标记录及其链上依赖记录，返回删除数量。
8. attest_batch：每个请求使用全新上下文独立校验，逐个返回 accepted 与 reason。

## 10 个规格缺陷

1. 载荷只含 nonce，不含公钥摘要，换公钥仍可复用。
2. 签名比较用普通等号，存在时序侧信道。
3. 链校验只验叶子，不逐级验证父签名。
4. 链深度按报价条数计算，缺父级不报错。
5. 绑定校验只比较 nonce 前缀，忽略公钥。
6. 时效只校验终止时间，未生效证明被接受。
7. 登记不检查已有登记者，可覆盖他人密钥。
8. 登记不幂等，同一密钥重复登记返回不同结果。
9. 吊销只删主记录，链上引用仍可用。
10. 批量校验复用链上下文，第二个请求沿用第一个请求的父键。

## 15 个测试

测试文件 tests/test_chain.py 恰好包含 15 个测试，覆盖上述 10 个缺陷，并额外覆盖合法链登记、中间级篡改、旧 nonce 重放、同一密钥重复登记稳定、批量与单独校验一致。

tests/test_chain.py 是评测契约，禁止修改、删除、跳过或弱化断言。考生只能实现 src/attest/chain.py，并保持 8 个公开函数签名不变。

## 题目字段

| 字段 | 值 |
| --- | --- |
| 分类 | 安全 |
| 方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 环境 | Python 3, pytest |
| 依赖 | 无外部依赖 |

## 评分要点

- 证明链必须从根到叶逐级验签，不能只验叶子。
- 载荷必须同时绑定 nonce 与公钥摘要，绑定校验不能做前缀匹配。
- 时效两端都包含，但窗口必须有限且证明寿命不能超过窗口。
- 同一密钥只登记一次；不同 owner 不得覆盖；重复登记返回原记录。
- 旧 nonce 不得用于另一个 key_id；吊销必须级联清除依赖记录。
- 批量请求之间不得共享父键、链深度或验签状态。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

