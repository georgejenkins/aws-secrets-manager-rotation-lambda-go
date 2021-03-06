# AWS Secrets Manager Custom Rotation Lambda for Golang

Based heavily on the Python version distributed by [AWS](https://github.com/aws-samples/aws-secrets-manager-rotation-lambdas/blob/master/SecretsManagerRotationTemplate/lambda_function.py), this lambda provides a wireframe for automated secret rotation for custom secrets in AWS Secrets Manager. I wanted to have a version in Go, as many other microservices I work on are also in Go, and although the official (Python) version works fine, I felt it more appropriate to consolidate my language choices.  


### How to customize for your own secret:

This lambda handles the transition of labels on Secret Manager stored secrets. You will need to write your own code for the __setSecret__ and __testSecret__ stages. 

#### Set Secret Stage
The __setSecret__ stage should set the __AWSPENDING__ secret in the service that the secret belongs to. For example, if you are wanting to rotate a password for a user in a database, this stage would connect to the database and update the password. 

#### Test Secret Stage
The __testSecret__ stage should validate that the __AWSPENDING__ secret works in the service that the secret belongs to. Following the previous example, this stage should attempt to use the new password in order to validate the update worked as expected. 


### How to build the lambda for deployment:

#### Unix:
```
GOOS=linux go build main.go
zip main.zip ./main
```

#### Windows (Powershell):
AWS provides a utility (__build-lambda-zip.exe__) to make it easier to create lambda Go packages. More information can be found on the official AWS [Lambda Deployment Package in Go
](https://docs.aws.amazon.com/lambda/latest/dg/lambda-go-how-to-create-deployment-package.html) guide, along with the download link for __build-lambda-zip.exe__.

```
$env:GOOS = "linux"
go build -o main main.go
~\Go\Bin\build-lambda-zip.exe -o main.zip main
```

