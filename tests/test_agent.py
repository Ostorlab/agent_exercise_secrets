"""Unittests for exercice secrets agent."""


def testExerciceSecretsAgent_whenRegexIsProvidedAndSecretExists_reportsFinding(
    agent_mock, secrets_agent, dummy_file_message):
    """Unit test for the Exercice Secrets Agent. Case where a regular expression is provided as argument, and target
    file matches. Should report the finding."""

    secrets_agent.process(dummy_file_message)

    assert len(agent_mock) == 1
    assert agent_mock[0].selector == 'v3.report.vulnerability'
    assert agent_mock[0].data['risk_rating'] == 'HIGH'