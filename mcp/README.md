# MCP servers

Configuración de servidores MCP para PurpleForge. La fuente de verdad vive en
esta carpeta; el `.mcp.json` de la raíz es un symlink a `mcp/azure.json`, así que
Claude Code carga esta config sin duplicarla.

## `azure.json` — Azure MCP Server (oficial de Microsoft)

Expone Azure a los agentes por lenguaje natural: consulta de recursos, quota de
vCPU, listado de imágenes/SKUs de VM y coste. Resuelve directamente los dos
blockers documentados en `AZURE-DEPLOY-RUNBOOK.md`:

- **Quota de vCPU por región** (blocker #1 de deploy): comprobar antes de escribir
  el spec o de gastar que el conteo de VMs cabe en la quota.
- **SKUs de imagen "best-effort"** (2022/2025, client-OS): verificar que la imagen
  y el `vm_size` existen en la región, en vez de `az vm image list` a mano.

Quién lo usa: `lab-designer` (validar `vm_size`/región/quota en diseño) y
`deploy-operator` (quota antes de gastar, coste-cero tras `destroy`).

### Requisitos

- `npx` (Node.js) en el PATH — el server se descarga solo con `npx -y @azure/mcp`.
- Autenticación: usa la credencial de Azure CLI existente. Ejecuta `az login`
  una vez (en esta sesión: `! az login`).

### Activación

El symlink de la raíz ya lo deja activo para este proyecto. Para verificar:

```bash
claude mcp list          # debe listar "azure"
```

Si prefieres registrarlo a mano en vez del symlink:

```bash
claude mcp add-json azure "$(cat mcp/azure.json | jq -c '.mcpServers.azure')"
```
