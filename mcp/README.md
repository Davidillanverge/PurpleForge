# MCP servers

Config de servidores MCP. La fuente de verdad vive aquí (un JSON por servidor);
el `.mcp.json` de la raíz los combina (`azure` + `purpleforge`) para que Claude
Code los cargue al abrir el repo.

## `purpleforge.json` — servidor MCP de PurpleForge (modo MCP)

El segundo modo de ejecución: **Claude Code es el LLM** (tu suscripción, sin API
key) y este servidor expone las operaciones de lab sobre la misma BD, máquina de
estados, servicios, ForgeTool y outcomes que el modo standalone. Lanza
`.venv/bin/python -m mcp_server` desde la raíz del repo y lee el mismo `.env`.

- Tools `lab_*` (list/status/create/design_start/design_finish/check/compile/
  generate/deploy/teardown/validate) + `approvals_pending`.
- Prompts `lab_designer`, `deploy_operator`, `purple_validator`, `catalog_author`
  construidos desde `.claude/agents/*.md`.
- `lab_deploy` / `lab_teardown` crean una aprobación pendiente y vuelven al
  instante: la decide un **humano en el dashboard** (Claude no puede aprobar).

Requisitos: `pip install -e ".[app,mcp]" -c constraints.txt` y el dashboard
levantado para aprobar (`uvicorn api.app:create_app --factory --app-dir src`).

## `azure.json` — Azure MCP Server (oficial)

Expone Azure por lenguaje natural: recursos, quota de vCPU, imágenes/SKUs de VM,
coste. Resuelve los dos blockers de `AZURE-DEPLOY-RUNBOOK.md`:

- **Quota de vCPU por región** (blocker #1): comprobar que las VMs caben antes de
  escribir el spec o gastar.
- **SKUs "best-effort"** (2022/2025, client-OS): verificar imagen + `vm_size` en
  la región sin `az vm image list` a mano.

Lo usan `lab-designer` (diseño) y `deploy-operator` (antes de gastar, coste-cero
tras `destroy`).

### Requisitos

- `npx` (Node.js) en el PATH — el server se descarga con `npx -y @azure/mcp`.
- Auth vía Azure CLI: `az login` una vez (`! az login`).

### Verificar / registrar

```bash
claude mcp list          # debe listar "azure" y "purpleforge"
# a mano, en vez de .mcp.json:
claude mcp add-json azure "$(cat mcp/azure.json | jq -c '.mcpServers.azure')"
```
