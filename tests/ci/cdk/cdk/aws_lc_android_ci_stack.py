# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from aws_cdk import core, aws_codebuild as codebuild, aws_iam as iam, aws_codepipeline as codepipeline, aws_s3 as s3, aws_codepipeline_actions as codepipeline_actions
from util.ecr_util import ecr_arn
from util.iam_policies import code_build_batch_policy_in_json, s3_read_write_policy_in_json
from util.metadata import AWS_ACCOUNT, AWS_REGION, GITHUB_REPO_OWNER, GITHUB_REPO_NAME
from util.yml_loader import YmlLoader


class AwsLcAndroidCIStack(core.Stack):
    """Define a stack used to batch execute AWS-LC tests in GitHub."""

    def __init__(self,
                 scope: core.Construct,
                 id: str,
                 ecr_repo_name: str,
                 spec_file_path: str,
                 **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        s3_bucket_name = "awslc-android-s3-bucket"

        # Define CodeBuild resource.
        git_hub_source = codebuild.Source.git_hub(
            owner=GITHUB_REPO_OWNER,
            repo=GITHUB_REPO_NAME,
            webhook=True,
            webhook_filters=[
                codebuild.FilterGroup.in_event_of(
                    codebuild.EventAction.PULL_REQUEST_CREATED,
                    codebuild.EventAction.PULL_REQUEST_UPDATED,
                    codebuild.EventAction.PULL_REQUEST_REOPENED)
            ],
            clone_depth=1)

        # Define S3 Bucket for android codebuild artifacts to output to.
        source_bucket = s3.Bucket(scope=self,
                  id="{}-s3".format(id),
                  bucket_name=s3_bucket_name,
                  block_public_access=s3.BlockPublicAccess.BLOCK_ALL)


        # Define a IAM role for this stack.
        code_build_batch_policy = iam.PolicyDocument.from_json(
            code_build_batch_policy_in_json([id])
        )
        s3_read_write_policy = iam.PolicyDocument.from_json(
            s3_read_write_policy_in_json(s3_bucket_name)
        )
        inline_policies = {"code_build_batch_policy": code_build_batch_policy, "s3_read_write_policy": s3_read_write_policy}
        role = iam.Role(scope=self,
                        id="{}-role".format(id),
                        assumed_by=iam.ServicePrincipal("codebuild.amazonaws.com"),
                        inline_policies=inline_policies)

        # Create build spec.
        placeholder_map = {"ECR_REPO_PLACEHOLDER": ecr_arn(ecr_repo_name)}
        build_spec_content = YmlLoader.load(spec_file_path, placeholder_map)

        # Define CodeBuild.
        project = codebuild.Project(
            scope=self,
            id=id,
            project_name=id,
            source=git_hub_source,
            role=role,
            timeout=core.Duration.minutes(180),
            environment=codebuild.BuildEnvironment(compute_type=codebuild.ComputeType.SMALL,
                                                   privileged=False,
                                                   build_image=codebuild.LinuxBuildImage.STANDARD_4_0),
            build_spec=codebuild.BuildSpec.from_object(build_spec_content),
            artifacts=codebuild.Artifacts.s3(
                bucket=source_bucket,
                include_build_id=False,
            )
        )

        # Create pipeline stages and stage
        source_output = codepipeline.Artifact(artifact_name="artifacts")
        source_action = codepipeline_actions.S3SourceAction(
            action_name="awslc-android-s3-bucket-src",
            bucket_key="apk-artifacts",
            bucket=source_bucket,
            output=source_output,
            trigger=codepipeline_actions.S3Trigger.EVENTS
        )

        # Provide a Stage when creating a pipeline
        # pipeline = codepipeline.Pipeline(self, "android-devicefarm-codepipeline")
        # source_stage = pipeline.add_stage(stage_name="codebuild-artifact-source", actions=[source_action])
        # build_stage = pipeline.add_stage(stage_name="android-codebuild", actions=[codebuild_action])


        # Define a IAM role for this stack.
        # code_build_batch_policy = iam.PolicyDocument.from_json(
        #     code_build_batch_policy_in_json([id])
        # )
        # inline_policies = {"code_build_batch_policy": code_build_batch_policy}
        # role = iam.Role(scope=self,
        #                 id="{}-role".format(id),
        #                 assumed_by=iam.ServicePrincipal("codebuild.amazonaws.com"),
        #                 inline_policies=inline_policies)

        # # Create build spec.
        # build_spec_content = YmlLoader.load("../android/aws-resources/buildspec.yml")

        # android_codebuild_project = codebuild.PipelineProject(self, "AndroidCodebuild",
        #     timeout=core.Duration.minutes(60),
        #     environment=codebuild.BuildEnvironment(compute_type=codebuild.ComputeType.SMALL,
        #                                            privileged=False,
        #                                            build_image=codebuild.LinuxBuildImage.STANDARD_4_0),
        #     build_spec=codebuild.BuildSpec.from_object(build_spec_content)
        # )

        # cfn_webhook = codepipeline.CfnWebhook(self, "android-codepipeline-webhook",
        #     authentication="UNAUTHENTICATED",
        #     authentication_configuration=
        #     codepipeline.CfnWebhook.WebhookAuthConfigurationProperty(
        #         # allowed_ip_range="allowedIpRange",
        #         # secret_token="secretToken"
        #     ),
        #     filters=[
        #         # codepipeline.CfnWebhook.WebhookFilterRuleProperty(
        #         # json_path="jsonPath",

        #         # # the properties below are optional
        #         # match_equals="matchEquals")
        #     ],
        #     target_action="android-codepipeline-src",
        #     target_pipeline="android-devicefarm-codepipeline",
        #     target_pipeline_version=7,

        #     # the properties below are optional
        #     name="android-codepipeline-webhook",
        #     register_with_third_party=False
        # )

        # source_output = codepipeline.Artifact(artifact_name="artifacts")
        # source_action = codepipeline_actions.GitHubSourceAction(
        #     action_name="android-codepipeline-src",
        #     output=source_output,
        #     owner=GITHUB_REPO_OWNER,
        #     repo=GITHUB_REPO_NAME,
        #     oauth_token=core.SecretValue.plain_text("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"),
        #     #oauth_token=core.SecretValue.secrets_manager("android-github-access"),
        #     variables_namespace="MyNamespace"
        # )

        # codebuild_action = codepipeline_actions.CodeBuildAction(
        #     action_name="android-codepipeline-build",
        #     project=android_codebuild_project,
        #     input=source_output,
        #     environment_variables={
        #         "COMMIT_URL": codebuild.BuildEnvironmentVariable(
        #             value=source_action.variables.commit_url
        #         )
        #     }
        # )

        # # Provide a Stage when creating a pipeline
        # pipeline = codepipeline.Pipeline(self, "android-devicefarm-codepipeline")
        # source_stage = pipeline.add_stage(stage_name="github-source", actions=[source_action])
        # build_stage = pipeline.add_stage(stage_name="android-codebuild", actions=[codebuild_action])

