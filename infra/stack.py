import json
from enum import Enum
from typing import Any, Dict, Optional, Sequence


from aws_cdk import (
    aws_iam as iam,
    aws_cognito as cognito,
    aws_cognito_identitypool_alpha as cognito_id_pool,
    aws_s3 as s3,
    aws_secretsmanager as secretsmanager,
    CfnOutput,
    custom_resources as cr,
    RemovalPolicy,
    SecretValue,
    Stack,
)
from constructs import Construct


class BucketPermissions(str, Enum):
    read_only = "r"
    read_write = "wr"


class AuthStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.userpool = self._create_userpool()
        self.domain = self._add_domain(self.userpool)
        self.identitypool = self._create_identity_pool(self.userpool)

        self._group_precedence = 0

        CfnOutput(
            self,
            f"userpool_id",
            export_name=f"userpool-id",
            value=self.userpool.user_pool_id,
        )
        CfnOutput(
            self,
            f"identitypool_id",
            export_name=f"identitypool-id",
            value=self.identitypool.identity_pool_id,
        )
        CfnOutput(
            self,
            f"identitypool_arn",
            export_name=f"identitypool-arn",
            value=self.identitypool.identity_pool_arn,
        )

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

    def _create_identity_pool(
        self, userpool: cognito.UserPool
    ) -> cognito_id_pool.IdentityPool:
        # TODO: Generate client for userpool that allows USER_PASSWORD_AUTH flow, pass to userpool provider
        client = self.add_programmatic_client(
            "cognito-identity-pool-auth-provider",
            name="Identity Pool Authentication Provider",
        )
        return cognito_id_pool.IdentityPool(
            self,
            "identity_pool",
            identity_pool_name=f"{Stack.of(self).stack_name} IdentityPool",
            authentication_providers=cognito_id_pool.IdentityPoolAuthenticationProviders(
                user_pools=[
                    cognito_id_pool.UserPoolAuthenticationProvider(
                        user_pool=userpool, user_pool_client=client
                    )
                ],
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
        self, service_id: str, name: Optional[str] = None
    ) -> cognito.UserPoolClient:
        client = self.userpool.add_client(
            service_id,
            auth_flows=cognito.AuthFlow(user_password=True),
            generate_secret=False,
            user_pool_client_name=name or service_id,
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
            f"{service_id}_client",
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

    @property
    def group_precedence(self):
        """
        Auto-incrementing property.
        """
        self._group_precedence += 1
        return self._group_precedence

    def add_cognito_group(
        self,
        group_name: str,
        description: str,
        bucket_permissions: Dict[str, BucketPermissions],
    ) -> cognito.CfnUserPoolGroup:

        role = iam.Role(
            self,
            f"{group_name}_role",
            assumed_by=iam.FederatedPrincipal(
                federated="cognito-identity.amazonaws.com",
                assume_role_action="sts:AssumeRoleWithWebIdentity",
                conditions={
                    "StringEquals": {
                        "cognito-identity.amazonaws.com:aud": self.identitypool.identity_pool_id
                    }
                },
            ),
        )

        for bucket_name, permission in bucket_permissions.items():
            bucket = s3.Bucket.from_bucket_name(
                self, f"{group_name}_{bucket_name}", bucket_name
            )
            if permission == BucketPermissions.read_write:
                bucket.grant_read_write(role)
            else:
                bucket.grant_read(role)

        return cognito.CfnUserPoolGroup(
            self,
            group_name,
            user_pool_id=self.userpool.user_pool_id,
            description=description,
            group_name=group_name,
            precedence=self.group_precedence,
            role_arn=role.role_arn,
        )
