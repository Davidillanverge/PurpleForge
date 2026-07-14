# MCP servers

Config de servidores MCP. La fuente de verdad vive aquí; el `.mcp.json` de la
raíz es un symlink a `mcp/azure.json`.

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
claude mcp list          # debe listar "azure"
# a mano, en vez del symlink:
claude mcp add-json azure "$(cat mcp/azure.json | jq -c '.mcpServers.azure')"
```
