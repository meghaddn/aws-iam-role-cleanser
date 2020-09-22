# IAM Role Cleanser

### Quick Start

```bash
git clone https://github.com/meghaddn/aws-iam-role-cleanup.git
cd aws-iam-role-cleanup

terraform init
terraform plan
terraform apply
```



### Documentation

##### Background

As we start building applications on AWS, lots of unused roles are left out in AWS account. This project will help to identify the roles which have not been used for a long period of time. The unused roles will be deleted.

#####  Deployment

This project makes use of 

- AWS Lambda
- Terraform

The deployment has been automated completely via Terraform

##### Configuration

There are parameters which can be configured via Terraform script

- *DAYS_UNUSED* environment variable  
- Cron job *schedule_expression* when the lambda function runs

##### Credentials

The Terraform script will take care of Lambda execution role which gives it necessary permissions.

##### Architecture

IAM Role Cleanser queries the IAM role information and when was it last used. If the role has not been used for last 90 days(DAYS_UNUSED) it will be a  3 step process.

- Instance Profiles attached to the role will be removed.
- Managed Policies will be detached from the role.
- Inline policies will be deleted from the role.

Once everything is removed from the role, the role will be deleted

##### Further improvements

Pull requests are more than welcome.

##### Acknowledgements

- https://aws.amazon.com/blogs/security/identify-unused-iam-roles-remove-confidently-last-used-timestamp/
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_manage_delete.html
- https://github.com/github/gitignore/blob/master/Python.gitignore
- https://docs.aws.amazon.com/code-samples/latest/catalog/python-iam-iam_basics-role_wrapper.py.html
- https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function
- https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule
- https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy
