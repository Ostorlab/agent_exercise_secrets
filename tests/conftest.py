"""Pytest fixtures for the exercise secrets agent."""
import pytest
import pathlib

from ostorlab.agent import message
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions

from agent import exercise_secrets_agent


@pytest.fixture()
def dummy_file_message():
    """Creates a dummy message of type v3.asset.file to be used by the agent for testing purposes."""
    file_content = (pathlib.Path(__file__).parents[0] / 'files/vulnerable_file.py').read_bytes()
    selector = 'v3.asset.file'
    msg_data = {'content': file_content, 'path': 'some/dummy/path'}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def secrets_agent():
    with (pathlib.Path(__file__).parent.parent / 'ostorlab.yaml').open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key='agent/ostorlab/nuclei',
            bus_url='NA',
            bus_exchange_topic='NA',
            args = []
        )

        agent_object = exercise_secrets_agent.AgentExerciseSecrets(definition, settings)
        return agent_object
