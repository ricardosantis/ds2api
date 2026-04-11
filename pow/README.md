# DeepSeek PoW 纯算实现

替代 `internal/deepseek/assets/sha3_wasm_bg.*.wasm` + wazero 运行时。

## 算法

DeepSeekHashV1 = SHA3-256 但 **Keccak-f[1600] 跳过 round 0** (只做 rounds 1..23)。其余参数不变:
rate=136, padding=0x06+0x80, output=32 字节。

PoW 协议:服务端选 answer ∈ [0, difficulty),计算 `challenge = hash(prefix + str(answer))`。
客户端遍历 [0, difficulty) 找到匹配的 nonce。

```
prefix = salt + "_" + str(expire_at) + "_"
input  = (prefix + str(nonce)).encode("utf-8")
hash   = DeepSeekHashV1(input)      → 32 bytes
header = base64(json({algorithm, challenge, salt, answer, signature, target_path}))
```

## 性能 (Apple M4, Go 1.25)

```
BenchmarkHash    187.5 ns/op    0 alloc    → 5.33M hash/s
BenchmarkSolve   13.4 ms/op    2 alloc    → 75 道/秒/核 (difficulty=144000)
```

对比 wazero 调 WASM: hash 快 **5×**, solve 快 **2.8×**。

## 测试

```bash
cd pow && go test -v ./... && go test -bench=. -benchmem
```

## 替换 WASM

替换 `internal/deepseek/pow.go` 中 `PowSolver.Compute`:

```go
// 原: 调 wasm_solve(retptr, chPtr, chLen, prefixPtr, prefixLen, difficulty)
// 新:
import "ds2api/pow"

func (c *Client) GetPow(ctx context.Context, a *auth.RequestAuth, ...) (string, error) {
    // ... 省略 token/retry 逻辑,只改 compute 部分 ...
    challenge, _ := bizData["challenge"].(map[string]any)
    ch := &pow.Challenge{
        Algorithm:  challenge["algorithm"].(string),
        Challenge:  challenge["challenge"].(string),
        Salt:       challenge["salt"].(string),
        ExpireAt:   int64(challenge["expire_at"].(float64)),
        Difficulty: int64(challenge["difficulty"].(float64)),
        Signature:  challenge["signature"].(string),
        TargetPath: challenge["target_path"].(string),
    }
    return pow.SolveAndBuildHeader(ch)
}
```

可删除:
- `internal/deepseek/assets/sha3_wasm_bg.*.wasm`
- `internal/deepseek/embedded_pow.go`
- `internal/deepseek/pow.go` 中 `PowSolver` 结构体、wazero 相关池化代码
- `go.mod` 中 `github.com/tetratelabs/wazero` 依赖
