"""
Timing helper - shared by the time-based SQL injection and command injection checks.

Idea: some bugs give no visible sign at all. But if our input can make the
server WAIT (SQL "SLEEP(3)" or shell "sleep 3"), the page comes back about
3 seconds later. That delay is the proof.

To avoid false alarms from a slow network, a payload only counts when:
  1. with a delay of N seconds the page is about N seconds slower,
  2. the SAME payload with a delay of 0 is fast again, and
  3. the slow request is slow a second time too.
"""


def seconds(response):
    """How long the server took to answer (requests measures this for us)."""
    return response.elapsed.total_seconds()


def find_time_delay(handler, point, param, original_value, payloads, delay):
    """Try timing payloads on one parameter.

    payloads: list of (label, template). The template uses {v} for the normal
              value, {d} for the number of seconds to wait and {p} for {d} + 1
              (used for "ping -n {p}", which takes about {d} seconds).
    Returns a dict with the evidence when a delay is confirmed, otherwise None.
    """
    if handler.timeout < delay * 2 + 2:
        return None  # the request would time out before we could measure the delay

    first = handler.send_payload(point, param, original_value)
    second = handler.send_payload(point, param, original_value)
    if first is None or second is None:
        return None
    normal_time = max(seconds(first), seconds(second))
    if normal_time > 5:
        return None  # the page is too slow to measure reliably

    def extra_time(template, wait):
        response = handler.send_payload(point, param, template.format(v=original_value, d=wait, p=wait + 1))
        return None if response is None else seconds(response) - normal_time

    for label, template in payloads:
        slow = extra_time(template, delay)
        if slow is None or slow < delay * 0.8:
            continue
        fast = extra_time(template, 0)              # same payload, no waiting
        if fast is None or fast > delay * 0.5:
            continue
        slow_again = extra_time(template, delay)    # repeat to rule out a slow network
        if slow_again is None or slow_again < delay * 0.8:
            continue
        return {
            "label": label,
            "evidence": (
                f"Normal response time: {normal_time:.2f}s\n"
                f"{param}={template.format(v=original_value, d=delay, p=delay + 1)} -> +{slow:.2f}s, "
                f"again -> +{slow_again:.2f}s\n"
                f"{param}={template.format(v=original_value, d=0, p=1)} -> +{fast:.2f}s\n"
                f"Payload style: {label}"
            ),
        }
    return None
