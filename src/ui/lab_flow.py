"""The lab's journey as the UI presents it: a stepper, ONE next step, and the rest.

The FSM (db.states) stays the source of truth — this only translates each state
into what a human should do next, in plain words, so the lab page never shows a
pile of equally-weighted buttons. Pure functions: easy to test, no I/O.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from db.states import INFRA_STATES, LabState

S = LabState

#: plain-language state names (the raw value stays visible as a tooltip)
STATE_LABELS: dict[LabState, str] = {
    S.DRAFT: "borrador",
    S.DESIGNING: "diseñando…",
    S.DESIGNED: "diseñado",
    S.COMPILED: "guardrail sin pasar",
    S.READY: "listo para aprobar",
    S.APPROVED: "aprobado",
    S.DEPLOYING: "desplegando…",
    S.DEPLOYED: "desplegado",
    S.VALIDATING: "validando…",
    S.VALIDATED: "validado",
    S.STOPPING: "parando…",
    S.STOPPED: "parado",
    S.STARTING: "encendiendo…",
    S.DESTROYING: "destruyendo…",
    S.DESTROYED: "destruido",
    S.FAILED: "fallido",
}

#: an operation (agent or no-AI forge run) owns the lab: no actions, show progress
BUSY_STATES = frozenset({S.DESIGNING, S.DEPLOYING, S.VALIDATING, S.STOPPING, S.STARTING, S.DESTROYING})

STAGES: list[tuple[str, str]] = [
    ("design", "Diseño"),
    ("compile", "Compilado"),
    ("approve", "Aprobado"),
    ("deploy", "Desplegado"),
    ("validate", "Validado"),
    ("operate", "En uso"),
    ("destroy", "Destruido"),
]
_IDX = {key: i for i, (key, _) in enumerate(STAGES)}

#: state → (stage it is working on / waiting at, that stage's status)
_STAGE_OF: dict[LabState, tuple[str, str]] = {
    S.DRAFT: ("design", "todo"),
    S.DESIGNING: ("design", "running"),
    S.DESIGNED: ("compile", "todo"),
    S.COMPILED: ("compile", "failed"),
    S.READY: ("approve", "todo"),
    S.APPROVED: ("deploy", "todo"),
    S.DEPLOYING: ("deploy", "running"),
    S.DEPLOYED: ("validate", "todo"),
    S.VALIDATING: ("validate", "running"),
    S.VALIDATED: ("operate", "current"),
    S.STOPPING: ("operate", "running"),
    S.STOPPED: ("operate", "current"),
    S.STARTING: ("operate", "running"),
    S.DESTROYING: ("destroy", "running"),
    S.DESTROYED: ("destroy", "done"),
}
#: where a FAILED lab failed, from the state it left
_FAILED_FROM = {S.DEPLOYING: "deploy", S.DESTROYING: "destroy", S.VALIDATING: "validate"}


@dataclass
class Stage:
    key: str
    label: str
    status: str  # done | current | todo | running | failed | pending


@dataclass
class NextStep:
    #: what the template renders as the primary card (see partials/lab_next_step.html)
    key: str
    title: str
    text: str
    #: secondary actions offered next to it (keys the template knows how to render)
    secondary: list[str] = field(default_factory=list)


def _failed_stage(transitions: Sequence[Any]) -> str:
    for t in reversed(list(transitions)):
        if getattr(t, "to_state", None) is S.FAILED:
            return _FAILED_FROM.get(t.from_state, "deploy")
    return "deploy"


def stages(state: LabState, transitions: Sequence[Any] = ()) -> list[Stage]:
    if state is S.FAILED:
        at, status = _failed_stage(transitions), "failed"
    else:
        at, status = _STAGE_OF[state]
    idx = _IDX[at]
    out = []
    for i, (key, label) in enumerate(STAGES):
        if state is S.DESTROYED:
            st = "done"
        elif i < idx:
            # destroying/failed-on-destroy: stages after "validate" were maybe never reached — still "done" path
            st = "done"
        elif i == idx:
            st = status
        else:
            st = "pending"
        out.append(Stage(key, label, st))
    if state in (S.STOPPED, S.STOPPING, S.STARTING):
        out[_IDX["operate"]].label = {S.STOPPED: "Parado", S.STOPPING: "Parando", S.STARTING: "Encendiendo"}[state]
    return out


def next_step(state: LabState, *, has_spec: bool, has_report: bool, validation_ok: bool | None = None) -> NextStep:
    """The ONE thing to do now, plus the few secondary actions that make sense.
    ``validation_ok``: the last validation report's verdict (None: never validated)."""
    rep = ["report"] if has_report else []
    if state is S.DRAFT:
        return NextStep(
            "design",
            "Diseña el lab",
            "Describe el lab que quieres y el agente lab-designer escribirá su spec "
            "(o asocia un specs/<nombre>.yml existente al crear el lab).",
        )
    if state in BUSY_STATES:
        return NextStep(
            "busy",
            {
                S.DESIGNING: "El agente está escribiendo el spec",
                S.DEPLOYING: "Desplegando el lab",
                S.VALIDATING: "Validando las vulnerabilidades",
                S.STOPPING: "Parando las VMs",
                S.STARTING: "Encendiendo el lab",
                S.DESTROYING: "Destruyendo el lab",
            }[state],
            "Hay una operación en curso; el resto de acciones vuelve cuando termine.",
            secondary=rep if state is not S.DESIGNING else [],
        )
    if state is S.DESIGNED:
        return NextStep(
            "compile",
            "Compila y comprueba el lab",
            "forge lab-spec valida el spec, calcula IPs, coste y la reconciliación hardening⟷vulns; "
            "el guardrail comprueba aislamiento, purple, reconciliación y ciclo de vida. No toca ningún cloud.",
            secondary=["check", "redesign_agent"],
        )
    if state is S.COMPILED:
        return NextStep(
            "compile",
            "El guardrail no ha pasado",
            "El spec compila pero incumple algún invariante. Corrige el spec (a mano o con el agente) "
            "y vuelve a compilar; los detalles salen al compilar.",
            secondary=["check", "redesign_agent"],
        )
    if state is S.READY:
        return NextStep(
            "approve",
            "Revisa y aprueba el despliegue",
            "El guardrail ha pasado. Revisa coste, aislamiento y reconciliación (abajo) y confirma "
            "que es un lab aislado de uso autorizado.",
            secondary=["redesign_agent"],
        )
    if state is S.APPROVED:
        return NextStep(
            "deploy",
            "Despliega el lab",
            "forge generate + forge deploy: Terraform, túnel WireGuard, Ansible (AD → población → hardening → "
            "vulns → EDR) y snapshot limpio. Crea infraestructura con coste; suele tardar 20–90 min.",
            secondary=["deploy_agent"],
        )
    if state is S.DEPLOYED:
        if validation_ok is False:
            return NextStep(
                "validate",
                "La validación no confirmó todas las vulns",
                "El lab solo queda validado cuando cada vuln está confirmada aplicada y explotable. Revisa el "
                "resumen y el reporte: las que requieren comprobación manual tienen su comando en el reporte; "
                "el agente IA puede intentarlas por ti. Vuelve a validar tras corregir.",
                secondary=[*rep, "validate_agent", "stop"],
            )
        return NextStep(
            "validate",
            "Valida el lab",
            "forge validate --run comprueba, por el túnel, que cada vuln está aplicada y es explotable. "
            "El lab queda validado solo si se confirman todas.",
            secondary=[*rep, "stop", "validate_agent"],
        )
    if state is S.VALIDATED:
        return NextStep(
            "report" if has_report else "operate",
            "El lab está listo para usar",
            "Consulta en el reporte hosts, accesos, credenciales, usuarios y defensa. "
            "Para ahorrar, páralo cuando no lo uses.",
            secondary=["validate", "stop", "validate_agent"] if has_report else ["validate", "stop"],
        )
    if state is S.STOPPED:
        return NextStep(
            "start",
            "Enciende el lab",
            "Arranca las VMs, levanta el túnel y comprueba conectividad (sin terraform apply). "
            "Parado solo cuesta el almacenamiento.",
            secondary=rep,
        )
    if state is S.FAILED:
        return NextStep(
            "teardown",
            "La operación falló: deja el lab a coste cero",
            "Puede haber recursos cloud facturando. La única salida es destruirlo (forge teardown verifica "
            "coste cero); después podrás redesplegarlo desde cero.",
            secondary=rep,
        )
    if state is S.DESTROYED:
        return NextStep(
            "redeploy",
            "Lab destruido (coste cero)",
            "Para volver a desplegarlo: preparar redespliegue (recompila + guardrail) → aprobar → desplegar. "
            "Mismo spec y mismo seed ⇒ el mismo lab, contraseñas incluidas.",
            secondary=["redesign_agent"] if has_spec else [],
        )
    return NextStep("none", STATE_LABELS.get(state, state.value), "")


def short_next(state: LabState) -> str:
    """One-line "what's next" for the dashboard."""
    return {
        S.DRAFT: "diseñar el spec",
        S.DESIGNING: "esperar al agente",
        S.DESIGNED: "compilar",
        S.COMPILED: "corregir el spec",
        S.READY: "aprobar despliegue",
        S.APPROVED: "desplegar",
        S.DEPLOYING: "en curso…",
        S.DEPLOYED: "validar",
        S.VALIDATING: "en curso…",
        S.VALIDATED: "usar · parar",
        S.STOPPING: "en curso…",
        S.STOPPED: "encender",
        S.STARTING: "en curso…",
        S.DESTROYING: "en curso…",
        S.DESTROYED: "redesplegar",
        S.FAILED: "destruir (coste cero)",
    }[state]


def can_generate(state: LabState) -> bool:
    """`forge generate` only without live infrastructure: regenerating a deployed lab
    overwrites the deploy-resolved backend.hcl and can orphan its Terraform state."""
    return state not in INFRA_STATES and state not in BUSY_STATES
