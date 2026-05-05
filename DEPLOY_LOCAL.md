# DS2API - Deploy

## Plataforma Ativa
**Heroku** — único deploy ativo.

> Vercel não está em uso. As variáveis `.env.vercel` e `.env.production` são mantidas apenas como referência local.

## URL
https://ds2api-1c052d209ba6.herokuapp.com

## Admin
- URL: `/admin/`
- Senha: `LeiaT+eo92veXs9FAOJa5A==`

## Versão
v4.4.2 (atualizado em 2026-05-05)

## API Keys
- `ds2-api-key-ricardo-2024`
- `ds2-backup-key-9876`

## Contas DeepSeek
| Email | Senha |
|-------|-------|
| ricardo.santis@gmail.com | qcwjPxGFgm4jZSn |
| ricardo.santis@live.com | qcwjPxGFgm4jZSn |
| marketing@drjo.com.br | qcwjPxGFgm4jZSn |

## Model Aliases
| Alias | Modelo |
|-------|--------|
| gpt-4o | deepseek-chat |
| gpt-5-codex | deepseek-reasoner |
| o3 | deepseek-reasoner |
| claude-sonnet-4-5 | deepseek-chat |
| claude-haiku-4-5 | deepseek-chat |
| claude-opus-4-6 | deepseek-reasoner |

## Claude Mapping
| Tier | Modelo |
|------|--------|
| fast | deepseek-chat |
| slow | deepseek-reasoner |

## Configuração ativa (config.json)
```json
{
  "claude_mapping": { "fast": "deepseek-chat", "slow": "deepseek-reasoner" },
  "responses": { "store_ttl_seconds": 900 },
  "embeddings": { "provider": "deterministic" },
  "auto_delete": { "mode": "none" },
  "current_input_file": { "enabled": true },
  "thinking_injection": { "enabled": true },
  "admin": { "jwt_expire_hours": 24 },
  "runtime": {
    "account_max_inflight": 2,
    "account_max_queue": 0,
    "global_max_inflight": 0,
    "token_refresh_interval_hours": 6
  }
}
```

## Variáveis de Ambiente (Heroku)
| Variável | Valor |
|----------|-------|
| `DS2API_ADMIN_KEY` | (ver .env.production) |
| `DS2API_JWT_SECRET` | (ver .env.production) |
| `DS2API_JWT_EXPIRE_HOURS` | 24 |
| `DS2API_VERCEL_INTERNAL_SECRET` | (ver .env.production) |
| `DS2API_VERCEL_PROTECTION_BYPASS` | (ver .env.production) |
| `LOG_LEVEL` | INFO |
| `DS2API_CONFIG_JSON` | Base64 do config.json (ver .env.production) |

## Como fazer novo deploy
```bash
git push heroku main
```

## Como atualizar o upstream
```bash
git fetch upstream
git merge upstream/main
git push origin main
git push heroku main
```
