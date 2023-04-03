import click

from fencer.api_spec import  APISpec
from fencer.sql_injection.sql_injection_endpoint import SQLInjectionEndpoint
from fencer.sql_injection.sql_injection_test_case_runner import InjectionTestCaseRunner
from fencer.test_case import TestResult, TestCase, AttackStrategy, TestDescription, HTTPMethods


class SQLInjectionTestRunner:
    def __init__(self, api_spec: APISpec):
        self.api_spec = api_spec
        self.injection_tests = 0
        self.reports = []

    def run_sql_injection_through_query_parameters(self):
        failing_tests = []
        for endpoint in self.api_spec.endpoints:
            sql_injection = SQLInjectionEndpoint(endpoint)
            endpoint_failing_tests = []
            click.echo(f"    {endpoint.method.upper()} {endpoint.base_url + endpoint.path.path}", nl=False)
            for url in sql_injection.get_urls_with_unsafe_query_params():
                self.injection_tests += 1
                test_case = InjectionTestCaseRunner(
                    test_case=TestCase(
                        category=AttackStrategy.INJECTION,
                        test_target="sql_injection__optional_query_parameters",
                        description=TestDescription(
                            http_method=getattr(HTTPMethods, endpoint.method.upper()),
                            url=url, base_url=endpoint.base_url, path=endpoint.path.path,
                            payload=endpoint.generate_safe_request_payload() if endpoint.has_request_payload() else None,
                        )
                    )
                )
                test_case.run()
                if test_case.test_case.result == TestResult.FAIL:
                    endpoint_failing_tests.append(test_case.test_case)
            if len(endpoint_failing_tests) > 0:
                failing_tests.extend(endpoint_failing_tests)
                click.echo(" 🚨")
            else:
                click.echo(" ✅")
        return failing_tests

    def run_sql_injection_through_path_parameters(self):
        failing_tests = []
        for endpoint in self.api_spec.endpoints:
            if not endpoint.has_path_params():
                continue
            sql_injection = SQLInjectionEndpoint(endpoint)
            endpoint_failing_tests = []
            click.echo(f"    {endpoint.method.upper()} {endpoint.base_url + endpoint.path.path}", nl=False)
            for url in sql_injection.get_urls_with_unsafe_path_params():
                self.injection_tests += 1
                test_case = InjectionTestCaseRunner(
                    test_case=TestCase(
                        category=AttackStrategy.INJECTION,
                        test_target="sql_injection__optional_query_parameters",
                        description=TestDescription(
                            http_method=getattr(HTTPMethods, endpoint.method.upper()),
                            url=url, base_url=endpoint.base_url, path=endpoint.path.path,
                            payload=endpoint.generate_safe_request_payload() if endpoint.has_request_payload() else None,
                        )
                    )
                )
                test_case.run()
                if test_case.test_case.result == TestResult.FAIL:
                    endpoint_failing_tests.append(test_case.test_case)
            if len(endpoint_failing_tests) > 0:
                failing_tests.extend(endpoint_failing_tests)
                click.echo(" 🚨")
            else:
                click.echo(" ✅")
        return failing_tests

    def run_sql_injection_through_request_payloads(self):
        failing_tests = []
        for endpoint in self.api_spec.endpoints:
            if not endpoint.has_request_payload():
                continue
            sql_injection = SQLInjectionEndpoint(endpoint)
            click.echo(f"    {endpoint.method.upper()} {endpoint.base_url + endpoint.path.path}", nl=False)
            self.injection_tests += 1
            test_case = InjectionTestCaseRunner(
                test_case=TestCase(
                    category=AttackStrategy.INJECTION,
                    test_target="sql_injection__optional_query_parameters",
                    description=TestDescription(
                        http_method=getattr(HTTPMethods, endpoint.method.upper()),
                        url=endpoint.safe_url, base_url=endpoint.base_url, path=endpoint.path.path,
                        payload=sql_injection.generate_unsafe_request_payload()
                    )
                )
            )
            test_case.run()
            if test_case.test_case.result == TestResult.FAIL:
                failing_tests.append(test_case.test_case)
                click.echo(" 🚨")
            else:
                click.echo(" ✅")
        return failing_tests