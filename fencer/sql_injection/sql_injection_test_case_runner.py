import requests
from fencer.test_case import TestResult, TestCase, VulnerabilitySeverityLevel


class InjectionTestCaseRunner:
    def __init__(self, test_case: TestCase):
        self.test_case = test_case
        self.response = None

    def run(self):
        callable_ = getattr(requests, self.test_case.description.http_method.value.lower())
        self.response = callable_(
            self.test_case.description.url, json=self.test_case.description.payload
        )
        self.resolve_test_result()

    def resolve_test_result(self):
        """
        In this case, it's difficult to assess the severity of the failure without looking
        at the backend logs. We'll assume that:
        - Failure to response indicates major outage caused by the request
        - 500 status code indicates potential high severity and potential for leaking traceback
        Everything else is severity Zero.
        Until we can develop better heuristics for response analysis, this is the best we can do.
        """
        # If the server fails to respond, we assume we broke it
        if self.response is None:
            self.test_case.result = TestResult.FAIL
            self.test_case.severity = VulnerabilitySeverityLevel.HIGH
        # If the request causes a server error, it likely broke it
        elif self.response.status_code >= 500:
            self.test_case.result = TestResult.FAIL
            self.test_case.severity = VulnerabilitySeverityLevel.HIGH
        # Any status code below 500 indicates the response was correctly processed
        # (i.e. correctly accepted or rejected)
        else:
            self.test_case.result = TestResult.SUCCESS
            self.test_case.severity = VulnerabilitySeverityLevel.ZERO
        self.test_case.ended_test()
