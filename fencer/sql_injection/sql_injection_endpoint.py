from dataclasses import dataclass
from random import choice
from typing import List, Callable, Generator, Optional, Union
from jsf import JSF

from fencer.api_spec import Endpoint, fake_parameter
from fencer.sql_injection.sql_injection_commands import sql_injection_commands


@dataclass
class SQLInjectionEndpoint:
    endpoint: Endpoint
    fake_param_strategy: Optional[Callable] = None
    sql_injection_commands: Optional[List[str]] = None
    fake_payload_strategy = None

    def __post_init__(self):
        self.sql_injection_commands = (
                self.sql_injection_commands or sql_injection_commands
        )
        self.fake_param_strategy = (
            self.fake_param_strategy or fake_parameter
        )
        self.fake_payload_strategy = (
            self.fake_payload_strategy or JSF
        )

    def get_safe_url_path_with_unsafe_required_query_params(self) -> List[Optional[str]]:
        urls = []
        for param in self.endpoint.required_query_params:
            for command in self.sql_injection_commands:
                param_value = f'?{param["name"]}={command}'
                other_params = [
                    other_param for other_param in self.endpoint.required_query_params
                    if other_param['name'] != param['name']
                ]
                if len(other_params) > 0:
                    param_value += '&'
                other_params = '&'.join(
                    f"{other_param['name']}={self.fake_param_strategy(param['schema'])}"
                    for other_param in other_params
                )
                url = self.endpoint.safe_url_path_without_query_params + param_value + other_params
                urls.append(url)
        return urls

    def get_safe_url_path_with_unsafe_optional_query_params(self) -> List[Optional[str]]:
        urls = []
        base_url = (
            self.endpoint.safe_url_path_with_safe_required_query_params
            if self.endpoint.has_required_query_params()
            else self.endpoint.safe_url_path_without_query_params
        )
        if self.endpoint.has_optional_query_params():
            for param in self.endpoint.optional_query_params:
                for command in self.sql_injection_commands:
                    param_value = f'?{param["name"]}={command}'
                    other_params = [
                        other_param for other_param in self.endpoint.optional_query_params
                        if other_param['name'] != param['name']
                    ]
                    if len(other_params) > 0:
                        param_value += '&'
                    other_params = '&'.join(
                        f"{other_param['name']}={self.fake_param_strategy(param['schema'])}"
                        for other_param in other_params
                    )
                    url = base_url + param_value + other_params
                    urls.append(url)
        return urls

    def get_unsafe_url_path_without_query_params(self) -> List[Optional[str]]:
        urls = []
        for param in self.endpoint.path.path_params_list:
            for command in self.sql_injection_commands:
                path = self.endpoint.path.path.replace(f'{{{param}}}', command)
                urls.append(self.endpoint.base_url + path)
        return urls

    def get_unsafe_url_path_with_safe_required_query_params(self) -> List[Optional[str]]:
        urls = []
        for base_url in self.get_unsafe_url_path_without_query_params():
            urls.append(
                base_url + '?'
                + '&'.join(f"{param['name']}={self.fake_param_strategy(param['schema'])}"
                           for param in self.endpoint.required_query_params)
            )
        return urls

    def get_urls_with_unsafe_query_params(self) -> Generator[str, None, None]:
        # Generator as type hint return:https://peps.python.org/pep-0484/#annotating-generator-functions-and-coroutines
        urls = []
        if self.endpoint.has_required_query_params():
            urls.extend(self.get_safe_url_path_with_unsafe_required_query_params())
        if self.endpoint.has_optional_query_params():
            urls.extend(self.get_safe_url_path_with_unsafe_optional_query_params())
        for url in urls:
            yield url

    def get_urls_with_unsafe_path_params(self) -> Generator[str, None, None]:
        # Generator as type hint return:https://peps.python.org/pep-0484/#annotating-generator-functions-and-coroutines
        urls = []
        if self.endpoint.path.has_path_params():
            urls.extend(self.get_unsafe_url_path_without_query_params())
            if self.endpoint.has_required_query_params():
                urls.extend(self.get_unsafe_url_path_with_safe_required_query_params())
        for url in urls:
            yield url

    def _inject_dangerous_sql_in_payload(self, payload: dict, schema: dict) -> Union[List, dict]:
        # need to include anyOf, allOf
        if schema['type'] == 'array':
            return [
                self._inject_dangerous_sql_in_payload(item, schema['items'])
                for item in payload
            ]
        if schema['type'] == 'object':
            # sometimes properties aren't specified so soft access
            for name, description in schema.get('properties', {}).items():
                # property may not be required
                if name not in payload:
                    continue
                if description['type'] == 'string':
                    payload[name] = choice(self.sql_injection_commands)
                if description['type'] == 'array':
                    payload[name] = self._inject_dangerous_sql_in_payload(
                        payload[name], description
                    )
        return payload

    def generate_unsafe_request_payload(self) -> Union[List, dict]:
        # this should be plural returning an array of payloads with different
        # sql injection strategies
        schema = self.endpoint.body['content']['application/json']['schema']
        if 'anyOf' in schema:
            schema = schema['anyOf'][0]
        payload = self.fake_payload_strategy(schema).generate()
        return self._inject_dangerous_sql_in_payload(payload, schema)
