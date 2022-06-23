"""ExerciceSecrets agent implementation : Agent responsible for looking into a file for any matches of a given regular expression."""
import logging
from rich import logging as rich_logging
import re

from ostorlab.agent import agent
from ostorlab.agent import message as m
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.agent.kb import kb


logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    level='INFO',
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger(__name__)


class AgentExerciceSecrets(agent.Agent, agent_report_vulnerability_mixin.AgentReportVulnMixin):
    """Agent responsible for looking into a file for any matches of a given regular expression."""

    def __init__(self, agent_definition: agent_definitions.AgentDefinition,
                 agent_settings: runtime_definitions.AgentSettings) -> None:
        """Init method.
        Args:
            agent_definition: Attributes of the agent.
            agent_settings: Settings of running instance of the agent.
        """
        super().__init__(agent_definition, agent_settings)
        self._reg_expression = self.args.get('reg_expression')


    def process(self, message: m.Message) -> None:
        """Process message of type v3.asset.file. Look for any matches of the given regular expression

        Args:
            message: Message containing the file to scan.

        """
        logger.info('processing message %s', message)
        file_content = message.data['content'].decode("utf-8")

        matched_secret = self._match_regex_to_file(file_content)
        if matched_secret is not []:
            technical_details = f'Found hardcoded secrets : {matched_secret}'
            kb_entry = kb.Entry(
                title = 'Hardcoded secret',
                risk_rating = agent_report_vulnerability_mixin.RiskRating.HIGH,
                references = {'reference1': 'http://www.dummy.com'},
                short_description = 'Lorem ipsum',
                description = 'Lorem ipsum',
                recommendation = 'Do not harcode your secrets for god sake.'
            )
            self.report_vulnerability(entry=kb_entry,
                                      technical_detail=technical_details,
                                      risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH)
        else:
            logger.info('File did not contain any secrets.')


    def _match_regex_to_file(self, content: str):
        """Find all matches of provided pattern in the content of the file."""
        return re.findall(self._reg_expression, content)


if __name__ == '__main__':
    logger.info('starting agent ...')
    AgentExerciceSecrets.main()
