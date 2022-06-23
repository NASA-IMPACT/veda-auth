import json
from typing import Any, Dict, Sequence

from aws_cdk import (
    aws_cognito as cognito,
    aws_secretsmanager as secretsmanager,
    CfnOutput,
    custom_resources as cr,
    RemovalPolicy,
    SecretValue,
    Stack,
)
from constructs import Construct


class AuthStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.userpool = self._create_userpool()
        CfnOutput(
            self,
            f"userpool_id",
            export_name=f"userpool_id",
            value=self.userpool.user_pool_id,
        )
        self.domain = self._add_domain(self.userpool)

    def _create_userpool(self) -> cognito.UserPool:
        return cognito.UserPool(
            self,
            "userpool",
            user_pool_name=Stack.of(self).stack_name,
            removal_policy=RemovalPolicy.DESTROY,
            self_sign_up_enabled=False,
            sign_in_aliases={"username": True, "email": True},
            sign_in_case_sensitive=False,
            standard_attributes=cognito.StandardAttributes(
                email=cognito.StandardAttribute(required=True)
            ),
        )

    def _add_domain(self, userpool: cognito.UserPool) -> cognito.UserPoolDomain:
        """
        Add a domain to a specified userpool
        """
        domain = userpool.add_domain(
            "cognito-domain",
            cognito_domain=cognito.CognitoDomainOptions(
                domain_prefix=Stack.of(self).stack_name
            ),
        )
        CfnOutput(
            self,
            "domain-base-url",
            export_name="userpool-domain-base-url",
            value=domain.base_url(),
        )
        return domain

    def _get_client_secret(self, client: cognito.UserPoolClient) -> str:
        # https://github.com/aws/aws-cdk/issues/7225#issuecomment-610299259
        describe_cognito_user_pool_client = cr.AwsCustomResource(
            self,
            f"describe-{client.to_string()}",
            resource_type="Custom::DescribeCognitoUserPoolClient",
            on_create=cr.AwsSdkCall(
                region=Stack.of(self).region,
                service="CognitoIdentityServiceProvider",
                action="describeUserPoolClient",
                parameters={
                    "UserPoolId": self.userpool.user_pool_id,
                    "ClientId": client.user_pool_client_id,
                },
                physical_resource_id=cr.PhysicalResourceId.of(
                    client.user_pool_client_id
                ),
            ),
            policy=cr.AwsCustomResourcePolicy.from_sdk_calls(
                resources=cr.AwsCustomResourcePolicy.ANY_RESOURCE,
            ),
        )
        return describe_cognito_user_pool_client.get_response_field(
            "UserPoolClient.ClientSecret"
        )

    def _create_secret(self, service_id: str, secret_dict: Dict[Any, Any]):
        """
        Create a secret to represent service credentials.
        """
        secret = secretsmanager.Secret(
            self,
            f"{service_id}-secret",
            secret_name=f"{Stack.of(self).stack_name}/{service_id}",
            description="Client secret, created by VEDA Auth CDK.",
            # TODO: Should we not do this? Perhaps the client secret should be placed in
            # a secret in a Lambda custom resource so as to avoid placing the secret in
            # CloudFormation template.
            secret_string_value=SecretValue.unsafe_plain_text(json.dumps(secret_dict)),
        )

        CfnOutput(
            self,
            f"{service_id}-secret-output",
            export_name=f"{service_id}-secret",
            value=secret.secret_name,
        )
        CfnOutput(
            self,
            f"{service_id}-secret-arn-output",
            export_name=f"{service_id}-secret-arn",
            value=secret.secret_arn,
        )

        return secret

    def add_resource_server(
        self, resource_id: str, supported_scopes: Dict[str, str]
    ) -> Dict[str, cognito.OAuthScope]:
        """
        The resource server represents something that a client would like to be able to
        access. Each scope represents a resource/action granted to an application.

        Args:
            resource_id: unique identifier for resource server
            available_scopes: dict mapping scope name to scope description

        Returns:
            mapping of scope name to OAuth resource server scope.
        """
        scopes = [
            cognito.ResourceServerScope(scope_name=name, scope_description=description)
            for name, description in supported_scopes.items()
        ]
        resource_server = self.userpool.add_resource_server(
            f"{resource_id}-server",
            identifier=f"{resource_id}-server",
            scopes=scopes,
        )
        return {
            scope.scope_name: cognito.OAuthScope.resource_server(resource_server, scope)
            for scope in scopes
        }

    def add_programmatic_client(
        self, service_id: str, scopes: Sequence[cognito.OAuthScope]
    ) -> cognito.UserPoolClient:
        client = self.userpool.add_client(
            service_id,
            auth_flows=cognito.AuthFlow(user_password=True),
            generate_secret=False,
            user_pool_client_name="Programmatic Access",
            disable_o_auth=True,
        )

        self._create_secret(
            service_id,
            {
                "flow": "user_password",
                "cognito_domain": self.domain.base_url(),
                "client_id": client.user_pool_client_id,
            },
        )

        return client

    def add_service_client(
        self, service_id: str, scopes: Sequence[cognito.OAuthScope]
    ) -> cognito.UserPoolClient:
        """
        Adds a client to the user pool that represents a service (ie not individual
        users). Client will utilize the OAuth2 client_credentials flow.
        """

        client = self.userpool.add_client(
            "service-access",
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(client_credentials=True),
                scopes=scopes,
            ),
            generate_secret=True,
            user_pool_client_name=f"{service_id} Service Access",
            disable_o_auth=False,
        )

        self._create_secret(
            service_id,
            {
                "flow": "client_credentials",
                "cognito_domain": self.domain.base_url(),
                "client_id": client.user_pool_client_id,
                "client_secret": self._get_client_secret(client),
                "scope": " ".join(scope.scope_name for scope in scopes),
            },
        )

        return client
