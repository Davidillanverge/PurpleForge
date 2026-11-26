"""The lab page's flow UI: every FSM state renders, offers ONE next step, and never offers
what can't work right now (e.g. regenerating scripts over live infrastructure)."""

from __future__ import annotations

import pytest
from _appkit import seed_lab
from test_ui import login

from db import repository as repo
from db.session import transaction
from db.states import INFRA_STATES, LabState
from ui import lab_flow

LAB = "winrm-validate-lab"
#: a path to every state from deployed (seed_lab reaches deployed itself)
_FROM_DEPLOYED = {
    LabState.DEPLOYED: [],
    LabState.VALIDATING: [LabState.VALIDATING],
    LabState.VALIDATED: [LabState.VALIDATING, LabState.VALIDATED],
    LabState.STOPPING: [LabState.STOPPING],
    LabState.STOPPED: [LabState.STOPPED],
    LabState.STARTING: [LabState.STOPPED, LabState.STARTING],
    LabState.DESTROYING: [LabState.DESTROYING],
    LabState.DESTROYED: [LabState.DESTROYING, LabState.DESTROYED],
    LabState.FAILED: [LabState.DESTROYING, LabState.FAILED],
}
_BEFORE = [LabState.DESIGNED, LabState.COMPILED, LabState.READY, LabState.APPROVED, LabState.DEPLOYING]


def test_every_state_has_a_label_a_stage_and_a_next_step():
    for state in LabState:
        assert lab_flow.STATE_LABELS[state] and lab_flow.short_next(state)
        stages = lab_flow.stages(state)
        assert len(stages) == len(lab_flow.STAGES)
        assert lab_flow.next_step(state, has_spec=True, has_report=True).title
        assert lab_flow.can_generate(state) == (state not in INFRA_STATES and state not in lab_flow.BUSY_STATES)


async def _lab_in(app, state):
    if state in _BEFORE:
        return await seed_lab(app, LAB, state)
    lab = await seed_lab(app, LAB, LabState.DEPLOYED)
    async with transaction(app.state.sessionmaker) as s:
        row = await repo.get_lab(s, "default", lab.id, for_update=True)
        for st in _FROM_DEPLOYED[state]:
            await repo.transition_lab(s, "default", row, st, actor="system")
    return lab


@pytest.mark.parametrize("state", [*_BEFORE, *_FROM_DEPLOYED])
async def test_lab_page_renders_in_every_state(client, state):
    lab = await _lab_in(client.app, state)
    ui = await login(client.app)
    r = await ui.get(f"/labs/{lab.id}")
    dash = await ui.get("/")
    await ui.aclose()
    assert r.status_code == 200 and dash.status_code == 200, r.text[-500:]
    page = r.text
    assert "siguiente paso" in page and "pf-steps" in page
    assert lab_flow.STATE_LABELS[state] in page
    if state in INFRA_STATES or state in lab_flow.BUSY_STATES:
        assert "/generate" not in page  # never regenerate over live infrastructure
    if state in lab_flow.BUSY_STATES:
        assert "/forge/" not in page and "zona peligrosa" not in page  # nothing to click mid-operation


async def test_generate_is_refused_with_live_infrastructure(client):
    lab = await seed_lab(client.app, LAB, LabState.DEPLOYED)
    r = await client.post(f"/api/labs/{lab.id}/generate")
    assert r.status_code == 409 and "live infrastructure" in r.json()["detail"]
