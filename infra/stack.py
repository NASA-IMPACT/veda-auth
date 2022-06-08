import json

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

    def _create_userpool(self) -> cognito.UserPool:
        userpool = cognito.UserPool(
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

        userpool.add_domain(
            "cognito-domain",
            cognito_domain=cognito.CognitoDomainOptions(
                domain_prefix="auth-playground"
            ),
        )

        return userpool

    def _get_client_secret(self, client: cognito.UserPoolClient) -> str:
        # https://github.com/aws/aws-cdk/issues/7225#issuecomment-610299259
        describe_cognito_user_pool_client = cr.AwsCustomResource(
            self,
            "DescribeCognitoUserPoolClient",
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
        describe_cognito_user_pool_client.node.add_dependency(client)
        describe_cognito_user_pool_client.node.add_dependency(self.userpool)

        return describe_cognito_user_pool_client.get_response_field(
            "UserPoolClient.ClientSecret"
        )

    def add_programmatic_client(self, service_id: str) -> cognito.UserPoolClient:
        client = self.userpool.add_client(
            "api-access",
            auth_flows=cognito.AuthFlow(user_password=True),
            generate_secret=False,
            user_pool_client_name="Programmatic Access",
            disable_o_auth=True,
        )

        CfnOutput(
            self,
            "programmatic-client-id",
            export_name="Programmatic-Client-ID",
            value=client.user_pool_client_id,
        )

        return client

    def add_service_client(self, service_id: str) -> cognito.UserPoolClient:
        """
        Adds a client to the user pool that represents a service (ie not individual
        users). Client will utilize the OAuth2 client_credentials flow.
        """
        service_scope = cognito.ResourceServerScope(
            scope_name=f"{service_id}",
            scope_description="Scope indicating that this is a service requesting access.",
        )

        resource_server = self.userpool.add_resource_server(
            f"{service_id}-resource-server",
            identifier=f"{service_id}-server",
            scopes=[service_scope],
        )

        client = self.userpool.add_client(
            "service-access",
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(client_credentials=True),
                scopes=[
                    cognito.OAuthScope.resource_server(resource_server, service_scope)
                ],
            ),
            generate_secret=True,
            user_pool_client_name=f"{service_id} Service Access",
            disable_o_auth=False,
        )

        secret = secretsmanager.Secret(
            self,
            f"{service_id}-secret",
            secret_name=f"{Stack.of(self).stack_name}/{service_id}/creds",
            secret_string_value=SecretValue(
                json.dumps(
                    {
                        "client_id": client.user_pool_client_id,
                        "client_secret": self._get_client_secret(client),
                    }
                )
            ),
        )

        CfnOutput(
            self,
            f"{service_id}-client-secret-arn",
            export_name=f"{service_id}-secret-arn",
            value=secret.secret_arn,
        )

        return client
