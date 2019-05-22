~/.aws/config:
```
[default]
region=<your region>
mfa_serial = <your MFA device's ARN>

[profile profile-0]
role_arn = arn:aws:iam::123456789012:role/MyAwesomeRole
source_profile = mfa
region = eu-west-1

[profile profile-1]
role_arn = arn:aws:iam::123456789012:role/MyAwesomeRole
source_profile = mfa
region = eu-west-1

[profile profile-2]
role_arn = arn:aws:iam::123456789012:role/MyAwesomeRole
source_profile = mfa
region = eu-west-1

[profile profile-3]
role_arn = arn:aws:iam::123456789012:role/MyAwesomeRole
source_profile = mfa
region = eu-west-1

...
```

~/.aws/credentials:
```
[default]
aws_access_key_id = <key-id>
aws_secret_access_key = <key-phrase>
```
