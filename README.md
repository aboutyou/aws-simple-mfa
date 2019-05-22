## AWS Simple MFA
This is a python script created to simplify the usage of MFA with AWS access keys.

### Motivation
If you have ever tried using AWS Access Keys with MFA then you probably know how painful it is, especially if you have to work with many AWS accounts. We work a lot with AWS CLI, develop with boto3 and use different tools that require AWS access keys. After failing to find a good solution to satisfy all our needs, this tool was created.

### Functionalities
* Create a temporary session with MFA token.
* Assume into a specified role via named profiles using MFA token.
* Generate a shell command to export Access Keys into environment variables (for development with boto3, for example).

### Requirements
 - Python 3
 - AWS CLI configured

Your AWS `credentials` and `config` files should be set as in [aws_cli_config.md](aws_cli_config.md). This is not totally necessary, but the script was tested using a configuration of this format.
It is important to set the `source_profile = mfa` for each of your named profiles.

### Installation
`pip3 install -r requirements.txt`

### Workflow
This script has the following logic:
1. Create a MFA session and write it to `~/.aws/credentials`. This step is skipped if MFA session exists and still active.
2. Use temporary credentials to assume into the role provided as an input parameter.
3. Write temporary credentials for the role to `~/.aws/credentials`.

This allows you to enter the MFA token once a day and then assume into roles for up to 1 hour (this is a limitation of AWS).

### Usage tips
Create an alias in your `~/.profile` to simplify usage of the script.
```
alias simple-mfa='python3 /path/to/aws-simple-mfa/simple-mfa.py'
```
After this you can do the following things:
1. Generate temporary Access Keys with your MFA token:
```
$ simple-mfa
Enter your MFA code:
123456
```
2. Use AWS CLI with an account from `profile-0` in your CLI config:
```
$ aws s3 ls --profile profile-0
```
3. Assume into a role defined in `profile-1` in your CLI config:
```
$ simple-mfa -r profile-1
```
4. Imagine you are developing code with boto3 that is supposed to run in an account defined in `profile-2` in your CLI config. You can use simple-mfa to export access secrets into environment variables:
```
$ simple-mfa -e role -r profile-2
INFO:root:The MFA token is still valid
Copy and paste the following to your terminal
export AWS_ACCESS_KEY_ID="<access-key>" && export AWS_SECRET_ACCESS_KEY="<secret-access-key>" && export AWS_SESSION_TOKEN="<session-token>"
```


### Supported platforms
The script was tested using the following environments:
1. MacOS High Sierra 10.13.6 with Python 3.7

### Future work
1. Windows support.
2. Support assuming into a role using long-term CLI credentials. This will give users an opportunity to assume into roles for up to 12 hours, but will require you to enter a MFA token for every role you assume into.
3. Unit tests.
4. Test on other platforms: Windows, Ubuntu...

### Bug reporting
If you found a bug or have a suggestion for improvement, the best way to make it happen is to create a pull request. Alternatively, you can create an issue and we will do our best to resolve it.

### License
This project is licensed under the terms of the **GNU General Public License v3.0** license.