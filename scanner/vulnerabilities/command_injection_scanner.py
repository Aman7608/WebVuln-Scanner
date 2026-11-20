"""
Command Injection Scanner.

Command injection happens when a website passes user input to a system
command, for example a "ping this address" page that runs:
    ping -c 4 <user input>
An attacker can add their own command after a ; or | and take over the server.

How we test (safely):
  We never run anything harmful. We only ask the shell to WAIT, e.g.
      127.0.0.1;sleep 3
  If the page comes back about 3 seconds later - and the same payload with
  "sleep 0" is fast again - the server ran our command. The timing logic is
  shared with the time-based SQL injection check (see timing.py).
  For Windows servers we use "ping -n 4 127.0.0.1", which takes about 3 s
  and only pings the server itself.
"""

import logging

from config import settings
from scanner.analysis.findings_collector import Finding
from scanner.engine.request_handler import RequestLimitReached
from scanner.vulnerabilities.timing import find_time_delay

logger = logging.getLogger(__name__)

# (label, payload) - {v} is the normal value, {d} the seconds to wait
COMMAND_PAYLOADS = [
    ("Linux/macOS shell ;", "{v};sleep {d}"),
    ("Linux/macOS shell |", "{v}|sleep {d}"),
    ("Linux/macOS shell &&", "{v}&&sleep {d}"),
    ("Linux/macOS shell $( )", "{v}$(sleep {d})"),
    ("Windows cmd &", "{v}&ping -n {p} 127.0.0.1"),   # {p} = d + 1 pings, about d seconds
]

DESCRIPTION = (
    "The value of this parameter is passed to a command on the server's operating "
    "system. An attacker could add their own commands and read files, install "
    "malware or take full control of the server."
)
REMEDIATION = (
    "Do not pass user input to shell commands. Use a library function instead "
    "(for example Python's socket module instead of calling ping). If a command "
    "is unavoidable, call it without a shell (subprocess.run([...], shell=False)) "
    "and only accept input that matches a strict allowlist, such as a valid IP address."
)


def scan_command_injection(handler, injection_points, collector):
    delay = settings.SQLI_TIME_DELAY
    for point in injection_points:
        for param in point.testable_params():
            # A harmless normal value, so a command like "ping <value>" finishes quickly
            original_value = point.params.get(param) or "127.0.0.1"
            try:
                result = find_time_delay(handler, point, param, original_value,
                                         COMMAND_PAYLOADS, delay)
            except RequestLimitReached:
                raise
            except Exception as error:
                logger.warning("Command injection test failed for %s %s: %s", point.url, param, error)
                continue
            if result:
                collector.add(Finding(
                    name="OS Command Injection (time-based)",
                    vuln_type="command_injection",
                    url=point.url, parameter=param, confidence="High",
                    description=DESCRIPTION, evidence=result["evidence"],
                    remediation=REMEDIATION,
                ))
