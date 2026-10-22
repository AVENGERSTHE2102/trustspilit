from fastapi.testclient import TestClient

from app.main import ActionProposal, BY_ID, app, evaluate_policy


def proposal(tool="read_file", resource="README.md", plan_step="Read README.md"):
    return ActionProposal(tool=tool, resource=resource, plan_step=plan_step)


def test_permits_exact_approved_normal_action():
    result = evaluate_policy(BY_ID["readme-injection"], proposal())
    assert result.decision.allowed
    assert result.action.trust == "trusted"
    assert all(result.decision.checks.values())


def test_blocks_unapproved_plan_step():
    result = evaluate_policy(BY_ID["readme-injection"], proposal(plan_step="Delete README.md"))
    assert not result.decision.allowed
    assert not result.decision.checks["approved_plan"]


def test_blocks_secret_resource_even_with_allowed_tool():
    result = evaluate_policy(BY_ID["readme-injection"], proposal(resource=".env", plan_step="Read README.md"))
    assert not result.decision.allowed
    assert result.action.trust == "untrusted"
    assert result.action.sensitive
    assert not result.decision.checks["trust_level"]
    assert not result.decision.checks["sensitive_data"]


def test_blocks_destructive_and_network_capabilities():
    scenario = BY_ID["readme-injection"]
    for action in (proposal("delete_file", "/production/data", "Read README.md"), proposal("http_post", "https://collector.invalid", "Read README.md")):
        result = evaluate_policy(scenario, action)
        assert not result.decision.allowed
        assert not result.decision.checks["capability"]


def test_policy_api_rejects_caller_supplied_approved_plan():
    client = TestClient(app)
    response = client.post("/api/policy/evaluate", json={
        "scenario_id": "readme-injection",
        "proposal": {"tool": "read_file", "resource": ".env", "plan_step": "Read README.md"},
        "approved_plan": ["Read .env"],
    })
    assert response.status_code == 422

