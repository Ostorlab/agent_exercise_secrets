"""ExerciseSecrets agent implementation.
Agent responsible for looking into a file for any matches of a given regular expression.
"""
import logging
from rich import logging as rich_logging
import re

from ostorlab.agent import agent
from ostorlab.agent import message as m
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


class AgentExerciseSecrets(agent.Agent, agent_report_vulnerability_mixin.AgentReportVulnMixin):
    """Agent responsible for looking into a file for any matches of a given regular expression."""

    def process(self, message: m.Message) -> None:
        """Process message of type v3.asset.file. Look for any matches of the given regular expression

        Args:
            message: Message containing the file to scan.

        """
        logger.info('processing message %s', message)
        file_content = message.data['content'].decode('utf-8')
        matched_secrets = self._match_regex_to_file(file_content, self.args.get('reg_expression'))
        if matched_secrets:
            for matched_secret in matched_secrets:
                technical_details = f'Found hardcoded secrets : {matched_secret.group()}'
                kb_entry = kb.Entry(
                    title='Hardcoded secret',
                    risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH,
                    references={'reference1': 'http://www.dummy.com'},
                    short_description='Lorem ipsum',
                    description='Lorem ipsum',
                    recommendation='Do not hardcode your secrets for god sake.'
                )
                self.report_vulnerability(entry=kb_entry,
                                          technical_detail=technical_details,
                                          risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH)
        else:
            logger.info('File did not contain any secrets.')

    def _match_regex_to_file(self, content: str, pattern: str):
        """Find all matches of provided pattern in the content of the file."""
        ## ToDo: add logic here.


if __name__ == '__main__':
    logger.info('starting agent ...')
    AgentExerciseSecrets.main()
